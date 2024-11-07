// SPDX-License-Identifier: GPL-3.0-or-later

package main

import "github.com/rbmk-project/common/selfsignedcert"

func main() {
	cert := selfsignedcert.New(selfsignedcert.NewConfigExampleCom())
	cert.WriteFiles("dnscoretest")
}
