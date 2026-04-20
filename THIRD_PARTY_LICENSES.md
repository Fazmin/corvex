# Third-party data licenses

The Corvex desktop binary embeds some third-party fingerprint data. Their
copyright notices and license terms are reproduced below, as required by
those licenses.

---

## Recog fingerprint database

**Location in the tree:** `crates/corvex-sonar/data/recog/*.xml`

**License:** BSD-2-Clause (Simplified BSD)

```
Copyright (c) 2013-present, Rapid7 LLC.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

Changes by this project: a curated subset of fingerprints is bundled.
File-level comments have been normalised. Fingerprint pattern bodies and
`<param>` elements are preserved.

---

## JARM

The JARM TLS-stack fingerprinting algorithm is reimplemented in
`crates/corvex-sonar/src/jarm.rs` from the public specification
(Apache-2.0 reference implementation by Salesforce). No upstream source is
redistributed.

---

## Nuclei templates

**Location in the tree:** `program/databases/nuclei/**/*.yaml`

**License:** MIT (ProjectDiscovery)

**Upstream:** https://github.com/projectdiscovery/nuclei-templates (tag v10.4.2, commit 8de881615f58b3427f0424338779d28de68d2ee1)

```
MIT License

Copyright (c) 2020-present ProjectDiscovery, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

Changes by this project: only a subset of the upstream template library is
bundled (templates whose `info.severity` is `critical`, `high`, or `medium`,
or whose tags include `kev`). The bundled set is refreshed by
`scripts/refresh-nuclei-bundle.sh`, which records the pinned upstream tag
and each template's commit SHA in `program/databases/nuclei/MANIFEST.toml`.
Per-template `info.author` attribution is preserved in the YAML and emitted
with every finding produced by the engine in
[crates/corvex-nuclei/](crates/corvex-nuclei/). Users who want the full
library can download it on demand into their local cache dir; those files
are not redistributed in this repo.
