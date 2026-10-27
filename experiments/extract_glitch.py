"""Extract RESULTS/ from the GLITCH docker image tar, applying layers in order
(including whiteout files), without running Docker."""
import json, os, shutil, sys, tarfile

src, dst = sys.argv[1], sys.argv[2]
outer = tarfile.open(src)
layers = json.load(outer.extractfile("manifest.json"))[0]["Layers"]
for L in layers:
    inner = tarfile.open(fileobj=outer.extractfile(L), mode="r|")
    for m in inner:
        if not m.name.startswith("RESULTS/"):
            continue
        base = os.path.basename(m.name)
        d = os.path.join(dst, os.path.dirname(m.name))
        if base == ".wh..wh..opq":
            if os.path.isdir(d):
                for x in os.listdir(d):
                    p = os.path.join(d, x)
                    shutil.rmtree(p) if os.path.isdir(p) and not os.path.islink(p) else os.remove(p)
            continue
        if base.startswith(".wh."):
            p = os.path.join(d, base[4:])
            if os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p)
            elif os.path.lexists(p):
                os.remove(p)
            continue
        if m.issym() or m.islnk():
            continue  # links are not needed for the data
        target = os.path.join(dst, m.name)
        if m.isdir():
            os.makedirs(target, exist_ok=True)
        elif m.isfile():
            os.makedirs(os.path.dirname(target), exist_ok=True)
            if os.path.isdir(target):
                shutil.rmtree(target)
            with open(target, "wb") as fh:
                shutil.copyfileobj(inner.extractfile(m), fh)
    print("applied", L, flush=True)
