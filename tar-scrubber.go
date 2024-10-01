package main

import (
	"archive/tar"
	"io"
	"os"
)

func main() {
	in := tar.NewReader(os.Stdin)

	out := tar.NewWriter(os.Stdout)
	defer out.Flush() // note: flush instead of close to avoid the empty block at EOF

	for {
		hdr, err := in.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err)
		}
		hdr.Uname = ""
		hdr.Gname = ""
		if err := out.WriteHeader(hdr); err != nil {
			panic(err)
		}
		if _, err := io.Copy(out, in); err != nil {
			panic(err)
		}
	}
}
