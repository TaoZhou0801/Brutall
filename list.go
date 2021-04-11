/*
	list.go consists of methods retrieving credentials and printing results.
*/

package main

import (
	"fmt"
	"os"
)

type mode byte

const (
	SING mode = iota + 1 // single password
	MULT                 // multiple passwords
	UNIQ                 // no username, single password
	PASS                 // no username, multiple passwords
)

type result byte

const (
	UNKNOWN result = iota
	FAILURE
	SUCCESS
	NOAUTH // no authentication
	NOPASS // no password needed
	GUEST  // guest access (accounts with higher authority may exist)
	SKIP   // skip current username
)

// either a "username" or a "password" object
type item struct {
	name string
	flag byte // bit vector of status, currently only the least significant bit is used
	// to indicate a successful pair was found under this username or password
}

// a list of login credentials
type list struct {
	ul []item // unique copy of usernames
	pl []item // unique copy of passwords

	ui []int   // slice of username indices
	pi [][]int // slice of slices of password indices, w.r.t. ul

	uc int // index of current username
	pc int // index of current password

	md mode // authentication mode
}

// initialize a new *list object from separate slices of usernames and passwords
func NewList(ul []string, pl []string) *list {
	l := new(list)

	// assign a "default" string to empty slice
	if len(ul) == 0 {
		ul = []string{"default"}
	}
	if len(pl) == 0 {
		pl = []string{"default"}
	}

	umap := make(map[string]bool)
	pmap := make(map[string]bool)

	// make unique copies of usernames and passwords
	for _, user := range ul {
		if !umap[user] {
			umap[user] = true
			l.ul = append(l.ul, item{name: user})
		}
	}
	for _, pass := range pl {
		if !pmap[pass] {
			pmap[pass] = true
			l.pl = append(l.pl, item{name: pass})
		}
	}

	// build slice of password index
	tmp := make([]int, len(l.pl))
	for i := range tmp {
		tmp[i] = i
	}

	// complete l.ui & l.pi
	l.ui = make([]int, len(l.ul))
	l.pi = make([][]int, len(l.ul))
	for i := range l.ui {
		l.ui[i] = i
		l.pi[i] = tmp
	}

	return l
}

// initialize a new *list object from a combo slice of usernames and passwords
func NewListCombo(cl [][2]string) *list {
	l := new(list)

	// assign a "default" pair to empty slice
	if len(cl) == 0 {
		cl = [][2]string{{"default", "default"}}
	}

	count := -1
	user, pass := "", ""
	ui, pi, ok := 0, 0, false
	umap := make(map[string]int)
	pmap := make(map[string]int)
	tmp := make(map[int]map[int]bool)

	// make unique copies of usernames and passwords
	for i := range cl {
		user = cl[i][0]
		pass = cl[i][1]

		if pi, ok = pmap[pass]; !ok {
			// new password object
			pi = len(l.pl)
			pmap[pass] = pi
			l.pl = append(l.pl, item{pass, 0})
		}

		if ui, ok = umap[user]; !ok {
			// new username object
			ui = len(l.ul)
			umap[user] = ui
			l.ul = append(l.ul, item{user, 0})

			count++
			l.ui = append(l.ui, ui)
			l.pi = append(l.pi, []int{pi})

			tmp[ui] = make(map[int]bool)
			tmp[ui][pi] = true

		} else if !tmp[ui][pi] {
			// new password under this username
			if ui == l.ui[count] {
				// same username as the last one
				l.pi[count] = append(l.pi[count], pi)
			} else {
				// different username from the last one
				count++
				l.ui = append(l.ui, ui)
				l.pi = append(l.pi, []int{pi})
			}
			tmp[ui][pi] = true
		}
	}

	return l
}

// call before reusing the list
func (l *list) Reset() {
	l.uc = 0
	l.pc = 0

	for _, obj := range l.ul {
		obj.flag = 0
	}
	for _, obj := range l.pl {
		obj.flag = 0
	}
}

// set authentication mode: UNIQ, PASS, SING, MULT
func (l *list) setMode(md mode) {
	// mode is immutable once set
	if l.md > 0 {
		return
	}

	l.md = md

	if md == UNIQ || md == PASS {
		l.ul = []item{{"default", 0}}
		l.ui = []int{0}
		tmp := make([]int, len(l.pl))
		for i := range tmp {
			tmp[i] = i
		}
		l.pi = [][]int{tmp}
	}
}

func (l *list) setDomain(domain string) {
	for i := range l.ul {
		l.ul[i].name += "@" + domain
	}
}

/************************************************************************
 *                         Retrieve Credential                          *
 ************************************************************************/

// check whether the list is exhausted
func (l *list) has() bool {
	if l.md == UNIQ || l.md == PASS {
		return l.uc < 1
	} else {
		return l.uc < len(l.ui)
	}
}

// retrieve the next credential
func (l *list) next() (string, string) {
	user, pass := l.ul[l.ui[l.uc]].name, l.pl[l.pi[l.uc][l.pc]].name
	if l.md == UNIQ || l.md == PASS {
		l.info("CHECK: password %s (%d of %d)", pass, l.pc+1, len(l.pi[l.uc]))
	} else {
		l.info("CHECK: username %s (%d of %d) password %s (%d of %d)",
			user, l.uc+1, len(l.ui), pass, l.pc+1, len(l.pi[l.uc]))
	}
	return user, pass
}

/************************************************************************
 *                             Print Result                             *
 ************************************************************************/

// set result
func (l *list) set(re result) {
	switch re {
	case SUCCESS:
		// record the successful pair found
		l.ul[l.ui[l.uc]].flag ^= 1
		l.pl[l.pi[l.uc][l.pc]].flag ^= 1

		if l.md == PASS || l.md == UNIQ {
			l.success("NO USERNAME | password %s", l.pl[l.pi[l.uc][l.pc]].name)
		} else {
			l.success("username %s | password %s", l.ul[l.ui[l.uc]].name, l.pl[l.pi[l.uc][l.pc]].name)
		}

		if l.md == SING {
			l.uc++
			l.pc = 0

			// successful usernames are skipped
			for l.ul[l.ui[l.uc]].flag^1 == 1 && l.has() {
				l.uc++
			}
		} else if l.md == UNIQ || len(l.pi[l.uc]) == l.pc+1 {
			l.uc++
			l.pc = 0
		} else {
			l.pc++
		}

	case FAILURE:
		if len(l.pi[l.uc]) == l.pc+1 {
			l.uc++
			l.pc = 0
		} else {
			l.pc++
		}

	case NOPASS:
		l.success("username %s | NO PASSWORD", l.ul[l.ui[l.uc]].name)
		fallthrough

	case SKIP:
		l.uc++
		l.pc = 0

	case NOAUTH:
		l.success("no authentication needed")

	case GUEST:
		l.success("guest access without authentication is allowed")
	}
}

// special set method for snmp v1, v2c only
func (l *list) setSNMP(pass string) {
	l.success("NO USERNAME | password %s", pass)
}

// write to os.Stdout a message prepended with the success tag and appended with a newline
func (l *list) success(format string, a ...interface{}) {
	os.Stdout.WriteString("\n[SUCCESS] ")
	fmt.Fprintf(os.Stdout, format, a...)
	os.Stdout.WriteString("\n\n")
}

// write to os.Stdout a message appended with a newline
func (l *list) info(format string, a ...interface{}) {
	fmt.Fprintf(os.Stdout, format, a...)
	os.Stdout.WriteString("\n")
}

// write to os.Stdout a message prepended with the warning tag and appended with a newline
func (l *list) warning(format string, a ...interface{}) {
	os.Stdout.WriteString("[WARNING] ")
	fmt.Fprintf(os.Stdout, format, a...)
	os.Stdout.WriteString("\n")
}

// write to os.Stderr a message prepended with the error tag and appended with a newline
func (l *list) error(format string, a ...interface{}) {
	os.Stderr.WriteString("[ERROR] ")
	fmt.Fprintf(os.Stderr, format, a...)
	os.Stderr.WriteString("\n")
}
