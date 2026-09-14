# hashmon

## About

- Linux program to generate multiple hash results from a file.

```
    ./hashmon --help
    Usage: ./hashmon [options] <filename>
    --format <text|json|csv>   Output format (default: text)
    --hash <name>              Hash algorithm(s), comma-separated or 'all' (default: all)
    --compare <hashfile>       Compare calculated hashes against a text hash list
    --help                     Show this help and exit

    Examples:
    ./hashmon file.txt
    ./hashmon --format json --hash sha256 file.txt
    ./hashmon --hash md5,sha256 *.bin
    ./hashmon --compare hashes.txt --hash sha256 file.txt
```

- Output Example:

```
    ./hashmon manual-test

    File: manual-test
    md5: 288692dd85da9be2c81acbb93a559e6a
    sha1: afe0252d30f66c9bf9341d3f14d0180b342b3301
    sha224: fda1e8a28f3373a8f2ba89d689ab903f1bf18757175cc50d20b6f6cb
    sha256: 76f4a69c1a977a0baa49f224602b47ed73fe94ff4e14a1504c229cb924c2e16c
    sha384: 18bb8440cb546a913f6dbfdf3e63d1619b3b14acdb174eaf15e4fb6e92a29eec326d8f445b15781983b790db8a740075
    sha512: d77dbf8457e17d72d01ca34b01663e5665a9d6673c2dd20efbab92572fa408f9facfa34ce668f1fe708c634b714eaebb5eadd3c8caba53ef8dc298c326c1470c
    crc32: 4d5640d1
    crc64: cfb98c869ed65a8c
```

## original development process

constructed in VS-Code by copilot (because Claude said I was out of my quota)

- Instead of upgrading my windows hashit, it ws easier to rewrite for linux
- so far currently only tested sha256
- no code review done
- development code prompt:
- have not verified that all the requested test exist yet

- AI prompt:
  > I want a c++ program called 'hashmon' for Ubuntu.
  > The code creates MD5, SHA1, SHA256, SHA512, CRC32, CRC64 and any other hash you think are important.
  > The output is typed to the screen as normal text out unless the user request otherwise.
  > The CLI input is filename to be test,
  > optional output options of json or csv (default to text),
  > a hash type request (default to all),
  > and optional text hashfile to compare the calculated hash output against for a match or no match.
  > The input filename could contain wild cards and, if so, provide output for each of the input files.  
  > If wildcard filename is provided, there is no need to compare results with a text hashfile.
  > Provide a CLI help output if requested or bad commands entered.
  > Keep each hash routine in a separate cpp files.
  > Provide test routines for each hash routine, including zero byte file, and a test file.
  > Provide test routines for bad parameters, no file, empty file as well as working code.

> Requested Claude, free version)
> ran for 5 minutes then said I used up my 5 hour limit, come back in 4.5 hours.
> said it created 9 files, but could not show me anything.

> Gave it to copilot in vs-code
> took about 10 minutes, watched it create code, test, find errors and write replacement code.
> At one point, copilot said it was "Feeding the hampsters"

> - the compare does not work like I think it should
> - had to get copilot to correct this

## plans

- maybe change compare to access a url if that is a standard
- Change compare to compare against pasted crc as well as compare a file with a hash code in a file
- add short CLI like -h for --hash
- consider modifing in a way that GUI line Nemo can show the data (results in popup windows instead of existing CLI)
- Add the exe download directly to github

## Build process:

- Using CMake

```
    cd /hashmon
    cmake -S . -B build
    cmake --build build -j2
```

- Test cases

```
    cd /hashmon
    cmake -S . -B build
    cmake --build build -j2
    ctest --test-dir build --output-on-failure
```
