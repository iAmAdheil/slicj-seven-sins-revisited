"""Run the authors' SLIC (puppet-lint + all_in_one.rb from the GLITCH package) on a
folder of Puppet scripts. Output: CSV PATH,LINE,ERROR in GLITCH's naming."""
import csv, os, re, subprocess, sys
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEMS = os.path.join(ROOT, "tools", "gems")
RULES = os.path.join(ROOT, "data", "glitch_rootfs", "RESULTS", "puppet", "SLIC_Puppet", "SPrules4pupp", "all_in_one.rb")
MAP = [("SECURITY:::HARD_CODED_SECRET_USER_NAME:::", "hardcoded-username"),
       ("SECURITY:::HARD_CODED_SECRET_PASSWORD:::", "hardcoded-password"),
       ("SECURITY:::HARD_CODED_SECRET_", "hardcoded-secret"),
       ("SECURITY:::EXPOSING_SECRET_LOCATION_", "hardcoded-secret"),
       ("SECURITY:::EMPTY_PASSWORD:::", "empty-password"), ("SECURITY:::HTTP:::", "use of http"),
       ("SECURITY:::BINDING_TO_ALL:::", "improper ip address binding"),
       ("SECURITY:::SUSPICOUS_COMMENTS:::", "suspicious comment"),
       ("SECURITY:::ADMIN_BY_DEFAULT:::", "admin-by-default"), ("SECURITY:::MD5:::", "weak cryptography algorithms")]
LINE = re.compile(r"(SECURITY:::[A-Z_0-9]+:::).* on line (\d+)")


def run(path):
    env = dict(os.environ, GEM_HOME=GEMS, GEM_PATH=GEMS)
    p = subprocess.run([os.path.join(GEMS, "bin", "puppet-lint"), "-l", RULES, path], capture_output=True, text=True,
                       env=env)
    rows = set()
    for ln in p.stdout.splitlines():
        m = LINE.search(ln)
        if not m:
            continue
        tag = m.group(1)
        err = next((e for pre, e in MAP if tag.startswith(pre)), None)
        if err:
            rows.add((os.path.basename(path), int(m.group(2)), err))
    return rows


def main(folder, out):
    files = [os.path.join(dp, f) for dp, _, fs in os.walk(folder) for f in fs if f.endswith(".pp")]
    with ThreadPoolExecutor(8) as ex:
        res = sorted(set().union(*ex.map(run, files))) if files else []
    with open(out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["PATH", "LINE", "ERROR"])
        w.writerows(res)
    print(len(files), "files", len(res), "rows ->", out)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
