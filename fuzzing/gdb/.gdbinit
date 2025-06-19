set auto-load safe-path .
set architecture aarch64
tbreak fuzz_one_input
commands
source ./gef.py
end
handle SIG33 nostop noprint pass