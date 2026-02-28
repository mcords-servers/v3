import subprocess
import sys
import os

# --- CONFIG ---
BLACKLIST = [
    # "test.c",
    # "auth.c",
    # "mem.c",
    # "old.c",
    # "old_main.c",
    # "temp_test.c",
    "ignore/"
]
# --------------

def is_blacklisted(path):
    """Check if a file or folder is in the blacklist (relative path)."""
    rel_path = os.path.relpath(path, ".")
    for item in BLACKLIST:
        if item.endswith("/"):  # Folder
            if rel_path.startswith(item):
                return True
        else:  # Exact file
            if rel_path == item:
                return True
    return False

def find_c_sources():
    return sorted(
        os.path.join(root, file)
        for root, _, files in os.walk('.')
        for file in files
        if file.endswith('.c') and not is_blacklisted(os.path.join(root, file))
    )

def get_sdl2_flags(sdl2=True):
    if (not sdl2): return []
    import shlex
    try:
        sdl_flags = subprocess.check_output(
            ["pkg-config", "--cflags", "--libs", "sdl2"],
            text=True
        )
        return shlex.split(sdl_flags)
    except subprocess.CalledProcessError:
        # fallback to sdl2-config if needed
        return []

def compile_sources(sources, output):
    print("📦 Compiling sources...")
    cmd = ["gcc", "-g","-fsanitize=address", "-I.", "-Istuff", "-Wall", "-Wno-deprecated-declarations", "-Wno-nonnull", "-o", output,
           "-L/usr/lib", "-lcurl", "-lm"] + get_sdl2_flags(False) + sources #, "-Dprintf(...)=my_printf(__VA_ARGS__)"
        #    "-L/usr/lib", "-lcrypto", "-lssl", "-lresolv", "-lcurl"] + sources #, "-Dprintf(...)=my_printf(__VA_ARGS__)"
    result = subprocess.run(cmd)
    return result.returncode == 0

def main():
    binary = "./proxy.o"
    sources = find_c_sources()

    if not sources:
        print("❌ No .c source files found (or all are blacklisted).")
        return

    print(f"🔍 Found sources: {', '.join(sources)}")
    if not compile_sources(sources, binary):
        print("❌ Compilation failed.")
        sys.exit(1)

    print("✅ Compilation successful.")
    print(f"🚀 Running: {binary} {' '.join(sys.argv[1:])}")
    if os.path.exists("asan.supp"):
        os.environ["ASAN_OPTIONS"] = "detect_leaks=1"
        os.environ["LSAN_OPTIONS"] = "suppressions=./asan.supp"
    os.execvp(binary, [binary] + sys.argv[1:])

if __name__ == "__main__":
    main()
