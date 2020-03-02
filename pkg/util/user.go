/*
Copyright 2020 Google LLC

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

package util

import (
	"fmt"
	"os"
	"os/user"
	"strconv"

	lcuser "github.com/opencontainers/runc/libcontainer/user"
)

const passwdPath = "/etc/passwd"

// LookupUser parses the /etc/passwd file for the given user name.
func LookupUser(username string) (*user.User, error) {
	return lookupFilter(passwdPath, func(u lcuser.User) bool {
		return u.Name == username
	})

}

// LookupUserID parses the /etc/passwd file for the given userID entry
func LookupUserID(userID string) (*user.User, error) {
	uid, err := strconv.Atoi(userID)
	if err != nil {
		return nil, fmt.Errorf("uid %q is not a valid integer value. %w", userID, err)
	}

	return lookupFilter(passwdPath, func(u lcuser.User) bool {
		return u.Uid == uid
	})

}

func lookupFilter(passwdPath string, filter func(u lcuser.User) bool) (*user.User, error) {
	fp, err := os.Open(passwdPath)
	if err != nil {
		return nil, err
	}
	defer fp.Close()

	users, err := lcuser.ParsePasswdFilter(fp, filter)
	if err != nil {
		return nil, err
	}

	if len(users) == 0 {
		return nil, user.UnknownUserError(fmt.Sprintf("user not found"))
	}

	return &user.User{
		Uid:      strconv.Itoa(users[0].Uid),
		Gid:      strconv.Itoa(users[0].Gid),
		Username: users[0].Name,
		HomeDir:  users[0].Home,
	}, nil
}
