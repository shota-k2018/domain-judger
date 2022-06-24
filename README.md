# domain-judger
## Installation

```
go get github.com/shota-k2018/domain-judger
```

## Example Usage

```go
package main

import (
	"github.com/shota-k2018/domain-judger"
	"log"
)

func main() {
	// If you want to verify the certificate, please set the second argument to ture
	log.Printf("judge: %+v", domain_judger.Judge("test", false))
}

```
