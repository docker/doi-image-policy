/*
   Copyright Docker DOI Image Policy authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

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
