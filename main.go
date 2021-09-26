package main

import "os"

var testlist = [][2]string{{"default", "1234567"}, {"admin", "1q2w3e4r"}, {"root", "123456"}, {"test", "123456"}}

var ul = []string{"admin", "zhoutao"}
var pl = []string{"zhoutao"}
var cl = [][2]string{{"test", "123456"}, {"root", "1q2w3e4r"}, {"admin", "1q2w3e4r"}, {"root", "654321"}}
var cl_s = [][2]string{{"test", "123456"}, {"zhoutao@dp.com", "1q2w3e4r"}}
var snmplist = []string{"public", "private", "123456", "admin"}

func main() {
	list := NewListCombo(testlist)
	// list := NewList(nil, snmplist)
	test := NewRedis("", os.Args[1], "", 10, list, false)
	test.Run()
}
