module dev.cengine/guest

go 1.25.0

require (
	github.com/hanwen/go-fuse/v2 v2.11.0
	github.com/klauspost/compress v1.18.7
	github.com/vishvananda/netlink v1.3.1
	github.com/vishvananda/netns v0.0.5
	golang.org/x/sys v0.44.0
)

replace github.com/hanwen/go-fuse/v2 => ./third_party/go-fuse
