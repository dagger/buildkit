package cache

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/containerd/containerd/leases"
	ctdsnapshots "github.com/containerd/containerd/snapshots"
	"github.com/containerd/continuity/fs"
	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/identity"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/snapshot"
	"github.com/moby/buildkit/snapshot/containerd"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/util/bklog"
	"github.com/moby/buildkit/util/leaseutil"
	"github.com/opencontainers/go-digest"
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

func (cm *cacheManager) GetOrInitVolume(ctx context.Context, key string, source ImmutableRef, sharingMode pb.CacheSharingOpt, sess session.Group) (_ MutableRef, rerr error) {
	// figure out the unique definition-based ID of the volume.
	idParts := []string{key}

	sourceChecksum, err := cm.volumeSourceContentHasher(ctx, source, sess)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate sourceChecksum: %w", err)
	}
	idParts = append(idParts, sourceChecksum.String())

	id := digest.FromString(strings.Join(idParts, "\x00")).Encoded()

	var parent *immutableRef
	if source != nil {
		if _, ok := source.(*immutableRef); ok {
			parent = source.Clone().(*immutableRef)
		} else {
			p, err := cm.Get(ctx, source.ID(), nil, NoUpdateLastUsed)
			if err != nil {
				return nil, err
			}
			parent = p.(*immutableRef)
		}
		if err := parent.Finalize(ctx); err != nil {
			return nil, err
		}
		if err := parent.Extract(ctx, sess); err != nil {
			return nil, err
		}
	}
	defer func() {
		if parent != nil {
			parent.Release(context.WithoutCancel(ctx))
		}
	}()

	rec, err := func() (_ *cacheRecord, rerr error) {
		cm.mu.Lock()
		defer cm.mu.Unlock()

		rec, err := cm.getRecord(ctx, id)
		switch {
		case err == nil:
			return rec, nil

		case errors.Is(err, errNotFound):
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
				WithDescription(fmt.Sprintf("cache mount %s (%s)", key, id)), // TODO: rest of metadata?
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

	// TODO: race condition here if someone grabs the record somehow before the lock below

	rec.mu.Lock()

	_, err = cm.volumeSnapshotter.Stat(ctx, id)
	exists := err == nil

	if !exists {
		l, err := cm.LeaseManager.Create(ctx, func(l *leases.Lease) error {
			l.ID = id
			l.Labels = map[string]string{
				"containerd.io/gc.flat": time.Now().UTC().Format(time.RFC3339Nano),
			}
			return nil
		})
		if err != nil && !cerrdefs.IsAlreadyExists(err) {
			rec.mu.Unlock()
			return nil, fmt.Errorf("failed to create lease: %w", err)
		}
		if cerrdefs.IsAlreadyExists(err) {
			l = leases.Lease{ID: id}
		}
		defer func() {
			if rerr != nil {
				ctx := context.WithoutCancel(ctx)
				if err := cm.LeaseManager.Delete(ctx, leases.Lease{
					ID: id,
				}); err != nil {
					bklog.G(ctx).Errorf("failed to remove lease: %+v", err)
				}
			}
		}()
		if err := cm.LeaseManager.AddResource(ctx, l, leases.Resource{
			ID:   id,
			Type: "snapshots/" + cm.volumeSnapshotter.Name(),
		}); err != nil && !cerrdefs.IsAlreadyExists(err) {
			rec.mu.Unlock()
			return nil, fmt.Errorf("failed to add snapshot %s resource to lease: %w", id, err)
		}

		var sourceSnapshotID string
		if parent != nil {
			sourceSnapshotID = sourceChecksum.Encoded()
			_, err := cm.volumeSnapshotter.Stat(ctx, sourceSnapshotID)
			sourceExists := err == nil

			if !sourceExists {
				if err := cm.LeaseManager.AddResource(ctx, l, leases.Resource{
					ID:   sourceSnapshotID,
					Type: "snapshots/" + cm.volumeSnapshotter.Name(),
				}); err != nil && !cerrdefs.IsAlreadyExists(err) {
					return nil, fmt.Errorf("failed to add source snapshot resource to lease: %w", err)
				}

				tmpActiveSnapshotID := identity.NewID()
				if _, err := cm.LeaseManager.Create(ctx, func(l *leases.Lease) error {
					l.ID = tmpActiveSnapshotID
					l.Labels = map[string]string{
						"containerd.io/gc.flat": time.Now().UTC().Format(time.RFC3339Nano),
					}
					return nil
				}, leaseutil.MakeTemporary); err != nil && !cerrdefs.IsAlreadyExists(err) {
					return nil, fmt.Errorf("failed to create lease for tmp active source snapshot: %w", err)
				}
				defer func() {
					ctx := context.WithoutCancel(ctx)
					if err := cm.LeaseManager.Delete(ctx, leases.Lease{
						ID: tmpActiveSnapshotID,
					}); err != nil {
						bklog.G(ctx).Errorf("failed to remove lease: %+v", err)
					}
				}()
				if err := cm.LeaseManager.AddResource(ctx, leases.Lease{
					ID: tmpActiveSnapshotID,
				}, leases.Resource{
					ID:   tmpActiveSnapshotID,
					Type: "snapshots/" + cm.volumeSnapshotter.Name(),
				}); err != nil && !cerrdefs.IsAlreadyExists(err) {
					return nil, fmt.Errorf("failed to add source snapshot resource to lease: %w", err)
				}

				if err := cm.volumeSnapshotter.Prepare(ctx, tmpActiveSnapshotID, ""); err != nil && !cerrdefs.IsAlreadyExists(err) {
					return nil, fmt.Errorf("failed to prepare source snapshot: %w", err)
				}
				newMntable, err := cm.volumeSnapshotter.Mounts(ctx, tmpActiveSnapshotID)
				if err != nil {
					return nil, fmt.Errorf("failed to get source mounts: %w", err)
				}
				newMnter := snapshot.LocalMounter(newMntable)
				newMntpoint, err := newMnter.Mount()
				if err != nil {
					return nil, fmt.Errorf("failed to mount new source snapshot: %w", err)
				}

				oldMntable, err := source.Mount(ctx, true, sess)
				if err != nil {
					newMnter.Unmount()
					return nil, fmt.Errorf("failed to get old source mounts: %w", err)
				}
				oldMnter := snapshot.LocalMounter(oldMntable)
				oldMntpoint, err := oldMnter.Mount()
				if err != nil {
					newMnter.Unmount()
					return nil, fmt.Errorf("failed to mount old source snapshot: %w", err)
				}

				if err := fs.CopyDir(newMntpoint, oldMntpoint, fs.WithAllowXAttrErrors()); err != nil {
					newMnter.Unmount()
					oldMnter.Unmount()
					return nil, fmt.Errorf("failed to copy source snapshot: %w", err)
				}

				newMnter.Unmount()
				oldMnter.Unmount()

				if err := cm.volumeSnapshotter.Commit(ctx, sourceSnapshotID, tmpActiveSnapshotID); err != nil {
					return nil, fmt.Errorf("failed to commit source snapshot: %w", err)
				}
			}
		}

		if err := cm.volumeSnapshotter.Prepare(ctx, id, sourceSnapshotID); err != nil && !cerrdefs.IsAlreadyExists(err) {
			rec.mu.Unlock()
			return nil, fmt.Errorf("failed to prepare volume: %w", err)
		}
	}
	rec.mu.Unlock()

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

	cm.seenVolumes.Store(id, struct{}{})

	return ref, nil
}

func (cm *cacheManager) snapshotterFor(md *cacheMetadata) snapshot.MergeSnapshotter {
	if md.GetRecordType() == client.UsageRecordTypeCacheMount {
		return cm.volumeSnapshotter
	}
	return cm.Snapshotter
}
