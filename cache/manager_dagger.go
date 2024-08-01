package cache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/containerd/containerd/leases"
	ctdsnapshots "github.com/containerd/containerd/snapshots"
	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/snapshot"
	"github.com/moby/buildkit/snapshot/containerd"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/util/bklog"
)

type AcquireSnapshotter interface {
	Acquire(ctx context.Context, key string, sharingMode pb.CacheSharingOpt) (func() error, error)
}

type CtdVolumeSnapshotter interface {
	ctdsnapshots.Snapshotter
	Name() string
	AcquireSnapshotter
}

type VolumeSnapshotter interface {
	snapshot.MergeSnapshotter
	AcquireSnapshotter
}

func newVolumeSnapshotter(ctx context.Context, ctdSnapshoter CtdVolumeSnapshotter, leaseManager leases.Manager) VolumeSnapshotter {
	return volumeSnapshotterAdapter{
		MergeSnapshotter: snapshot.NewMergeSnapshotter(ctx, containerd.NewSnapshotter(
			ctdSnapshoter.Name(),
			ctdSnapshoter,
			"buildkit",
			nil, // no idmapping
		), leaseManager),
		base: ctdSnapshoter,
	}

}

type volumeSnapshotterAdapter struct {
	snapshot.MergeSnapshotter
	base CtdVolumeSnapshotter
}

var _ VolumeSnapshotter = (*volumeSnapshotterAdapter)(nil)

func (sn volumeSnapshotterAdapter) Acquire(ctx context.Context, key string, sharingMode pb.CacheSharingOpt) (func() error, error) {
	return sn.base.Acquire(ctx, key, sharingMode)
}

func (cm *cacheManager) GetOrInitVolume(
	ctx context.Context,
	id string,
	sharingMode pb.CacheSharingOpt,
	parent ImmutableRef,
) (_ MutableRef, rerr error) {
	// TODO: support parent ref
	if parent != nil {
		return nil, fmt.Errorf("parent ref is not supported")
	}
	parentID := ""

	rec, err := func() (_ *cacheRecord, rerr error) {
		cm.mu.Lock()
		defer cm.mu.Unlock()

		rec, err := cm.getRecord(ctx, id)
		switch {
		case err == nil:
			return rec, nil

		case errors.Is(err, errNotFound):
			// TODO: more optimal to Lease+Prepare outside of manager lock, could put in rec lock?

			l, err := cm.LeaseManager.Create(ctx, func(l *leases.Lease) error {
				l.ID = id
				l.Labels = map[string]string{
					"containerd.io/gc.flat": time.Now().UTC().Format(time.RFC3339Nano),
				}
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create lease: %w", err)
			}
			// TODO: this defer should run outside this function too
			defer func() {
				if rerr != nil {
					ctx := context.WithoutCancel(ctx)
					if err := cm.LeaseManager.Delete(ctx, leases.Lease{
						ID: l.ID,
					}); err != nil {
						bklog.G(ctx).Errorf("failed to remove lease: %+v", err)
					}
				}
			}()

			if err := cm.LeaseManager.AddResource(ctx, l, leases.Resource{
				ID:   id,
				Type: "snapshots/" + cm.volumeSnapshotter.Name(),
			}); err != nil && !cerrdefs.IsAlreadyExists(err) {
				return nil, fmt.Errorf("failed to add snapshot %s resource to lease: %w", id, err)
			}

			if err := cm.volumeSnapshotter.Prepare(ctx, id, parentID); err != nil {
				return nil, fmt.Errorf("failed to prepare volume: %w", err)
			}

			md, _ := cm.getMetadata(id)

			rec = &cacheRecord{
				mu:            &sync.Mutex{},
				mutable:       true,
				cm:            cm,
				refs:          make(map[ref]struct{}),
				cacheMetadata: md,
			}

			opts := []RefOption{
				WithRecordType(client.UsageRecordTypeCacheMount),
				WithDescription(fmt.Sprintf("cache mount %s", id)), // TODO: support human readable name?
				CachePolicyRetain,
				withSnapshotID(id),
			}
			if err := initializeMetadata(rec.cacheMetadata, rec.parentRefs, opts...); err != nil {
				return nil, err
			}
			// this is needed because for some reason snapshotID is an imageRefOption
			if err := setImageRefMetadata(rec.cacheMetadata, opts...); err != nil {
				return nil, fmt.Errorf("failed to append image ref metadata to ref %s: %w", id, err)
			}

			cm.records[id] = rec
			return rec, nil

		default:
			return nil, fmt.Errorf("failed to get volume cache record: %w", err)
		}
	}()
	if err != nil {
		return nil, err
	}

	releaseFunc, err := cm.volumeSnapshotter.Acquire(ctx, id, sharingMode)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire volume: %w", err)
	}
	defer func() {
		if rerr != nil {
			rerr = errors.Join(rerr, releaseFunc())
		}
	}()

	rec.mu.Lock()
	defer rec.mu.Unlock()

	// TODO: note about how we are creating multiple mutable refs on a cacheRecord but it is safe to do so it turns out
	ref := rec.mref(true, DescHandlers{})
	ref.releaseFunc = releaseFunc
	return ref, nil
}

func (cm *cacheManager) snapshotterFor(md *cacheMetadata) snapshot.MergeSnapshotter {
	if md.GetRecordType() == client.UsageRecordTypeCacheMount {
		return cm.volumeSnapshotter
	}
	return cm.Snapshotter
}
