#if os(Linux)
    import Glibc
#else
    import Darwin
#endif


func start() {
    setbuf(stdout, nil);
    setbuf(stdin, nil);

    print("Please choose a password: ", terminator: "")

    let input = readLine()!

    if validate(input) {
        print("Congratulations! You have successfully chosen a password.")

        let flag = getenv("FLAG")
        if flag != nil {
            print(String(cString: flag!))
        }
    }
}

func validate(_ password: String) -> Bool {
    if password.count < 5 || password.count > 10 {
        print("Your password must be between 5 and 10 characters.")
        return false
    }

    if password.filter({ ("a"..."z").contains($0) }).isEmpty {
        print("Your password must include a lowercase letter.")
        return false
    }

    if password.filter({ ("A"..."Z").contains($0) }).isEmpty {
        print("Your password must include an uppercase letter.")
        return false
    }

    if password.filter({ $0.isNumber }).isEmpty {
        print("Your password must include a digit.")
        return false
    }

    if password.filter({ "!#$%&()*+,-./:;<=>?@[]^_`{|}~".contains($0) }).isEmpty {
        print("Your password must include a symbol.")
        return false
    }

    if password.uppercased().count == password.count {
        print("Your password must be a different length in uppercase.")
        return false
    }

    if String(password.reversed()) != password {
        print("Your password must be a palindrome.")
        return false
    }

    if Set(password.utf16).count != password.utf16.count {
        print("Your password must not contain the same character twice.")
        return false
    }

    return true
}

start()
