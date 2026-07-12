package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distFS embed.FS

func GetFS() (fs.FS, error) {
	// 返回 dist 目录的子文件系统，这样访问时无需带 dist 前缀
	return fs.Sub(distFS, "dist")
}
