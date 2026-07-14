module dev.cengine/guest

go 1.25.0

require (
	github.com/go-git/go-billy/v5 v5.9.0
	github.com/klauspost/compress v1.18.0
	github.com/vishvananda/netlink v1.3.1
	github.com/vishvananda/netns v0.0.5
	github.com/willscott/go-nfs v0.0.4
	golang.org/x/sys v0.43.0
)

replace github.com/willscott/go-nfs => ./third_party/go-nfs

require (
	github.com/cyphar/filepath-securejoin v0.6.1 // indirect
	github.com/rasky/go-xdr v0.0.0-20170124162913-1a41d1a06c93 // indirect
	github.com/willscott/go-nfs-client v0.0.0-20240104095149-b44639837b00 // indirect
)
