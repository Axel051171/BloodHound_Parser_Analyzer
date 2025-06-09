import os
import json
import argparse
import sys
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from abc import ABC, abstractmethod
from time import time
from datetime import datetime
from typing import List
from collections import Counter

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class AnalysisTask(ABC):
    output_filename = "output.txt"
    @abstractmethod
    def run(self, data: dict) -> List[str]: pass

# Analyseklassen (bestehend + neue)
class KerberoastAnalysis(AnalysisTask):
    output_filename = "kerberoastable_users.txt"
    def run(self, data): return [u["Properties"]["name"] for u in data.get("users", []) if u["Properties"].get("hasspn")]

class ASREPUserAnalysis(AnalysisTask):
    output_filename = "asrep_roastable_users.txt"
    def run(self, data): return [u["Properties"]["name"] for u in data.get("users", []) if u["Properties"].get("dontreqpreauth")]

class AdminUserAnalysis(AnalysisTask):
    output_filename = "admin_users.txt"
    def run(self, data): return [r["StartNode"] for r in data.get("relationships", []) if r.get("EdgeType") == "AdminTo"]

class SessionAnalysis(AnalysisTask):
    output_filename = "active_sessions.txt"
    def run(self, data): return [s["UserName"] for s in data.get("sessions", []) if s.get("UserName")]

class EnabledUserAnalysis(AnalysisTask):
    output_filename = "enabled_users.txt"
    def run(self, data): return [u["Properties"]["name"] for u in data.get("users", []) if u["Properties"].get("enabled")]

class OldComputerAnalysis(AnalysisTask):
    output_filename = "old_computers.txt"
    def run(self, data):
        now = int(datetime.utcnow().timestamp())
        return [c["Properties"]["name"] for c in data.get("data", []) if now - int(c["Properties"].get("lastlogontimestamp", 0)) > 180*86400]

class UnsupportedOSAnalysis(AnalysisTask):
    output_filename = "unsupported_os.txt"
    def run(self, data):
        unsupported = ("2003", "2008", "XP", "Vista", "7")
        return [c["Properties"]["name"] for c in data.get("data", []) if any(v in c["Properties"].get("operatingsystem", "") for v in unsupported)]

class NonWin10ProAnalysis(AnalysisTask):
    output_filename = "non_win10pro_machines.txt"
    def run(self, data):
        return [c["Properties"]["name"] for c in data.get("data", []) if "Windows 10 Pro" not in c["Properties"].get("operatingsystem", "")]

class DomainUserListAnalysis(AnalysisTask):
    output_filename = "domain_user_list.txt"
    def run(self, data):
        return [u["Properties"].get("samaccountname") for u in data.get("users", []) if u["Properties"].get("samaccountname")]

# Neue user.json-Auswertungen
class NeverChangedPasswordUsers(AnalysisTask):
    output_filename = "never_changed_passwords.txt"
    def run(self, data):
        return [u["Properties"]["name"] for u in data.get("users", []) if u["Properties"].get("pwdlastset") == 0]

class InactiveUserAccounts(AnalysisTask):
    output_filename = "inactive_users.txt"
    def __init__(self, days=180): self.cutoff = int(datetime.utcnow().timestamp()) - days * 86400
    def run(self, data):
        return [u["Properties"]["name"] for u in data.get("users", []) if u["Properties"].get("lastlogontimestamp", 0) < self.cutoff]

class NoPasswordRequiredUsers(AnalysisTask):
    output_filename = "no_password_required.txt"
    def run(self, data):
        return [u["Properties"]["name"] for u in data.get("users", []) if u["Properties"].get("dontreqpass")]

class UsersWithLogonScript(AnalysisTask):
    output_filename = "users_with_logonscript.txt"
    def run(self, data):
        return [u["Properties"]["name"] for u in data.get("users", []) if u["Properties"].get("logonscript")]

class MultiGroupUsers(AnalysisTask):
    output_filename = "multi_group_users.txt"
    def run(self, data):
        return [u["Properties"]["name"] for u in data.get("users", []) if len(u.get("MemberOf", [])) > 5]

# Parser-Klasse
class BloodHoundParser:
    TASK_FILE_MAPPING = {
        KerberoastAnalysis: ("users.json", "users"),
        ASREPUserAnalysis: ("users.json", "users"),
        AdminUserAnalysis: ("groups.json", "relationships"),
        SessionAnalysis: ("sessions.json", "sessions"),
        EnabledUserAnalysis: ("users.json", "users"),
        OldComputerAnalysis: ("computers.json", "data"),
        UnsupportedOSAnalysis: ("computers.json", "data"),
        NonWin10ProAnalysis: ("computers.json", "data"),
        DomainUserListAnalysis: ("users.json", "users"),
        NeverChangedPasswordUsers: ("users.json", "users"),
        InactiveUserAccounts: ("users.json", "users"),
        NoPasswordRequiredUsers: ("users.json", "users"),
        UsersWithLogonScript: ("users.json", "users"),
        MultiGroupUsers: ("users.json", "users"),
    }

    def __init__(self, input_dir, output_dir):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def load_json_combined(self, suffix):
        combined = []
        for file in self.input_dir.glob(f"*{suffix}"):
            try:
                with open(file, encoding="utf-8") as f:
                    data = json.load(f)
                    for key in ("users", "relationships", "sessions", "data"):
                        if isinstance(data.get(key), list):
                            combined.extend(data[key])
                            break
            except Exception as e:
                logging.warning(f"Fehler beim Laden von {file}: {e}")
        return combined

    def run_analysis(self, tasks, threads=4):
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {}
            for task in tasks:
                cls = type(task)
                file_suffix, key = self.TASK_FILE_MAPPING.get(cls, (None, None))
                if not file_suffix:
                    logging.error(f"Kein Mapping für {cls.__name__}")
                    continue
                data = self.load_json_combined(file_suffix)
                future = executor.submit(self.execute_task, task, {key: data})
                futures[future] = task

            for future in as_completed(futures):
                task = futures[future]
                try:
                    result, duration = future.result()
                    if result:
                        self.write_output(task, result)
                        logging.info(f"{task.output_filename}: {len(result)} Einträge in {duration:.2f}s")
                    else:
                        logging.info(f"{task.output_filename}: keine Einträge – Datei nicht erstellt.")
                except Exception as e:
                    logging.error(f"Analyse {task.__class__.__name__} fehlgeschlagen: {e}")

    def execute_task(self, task, data):
        start = time()
        result = task.run(data)
        return result, time() - start

    def write_output(self, task, lines):
        path = self.output_dir / task.output_filename
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(f"{line}\n" for line in lines)

# Argumente + CLI
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("input_dir")
    parser.add_argument("-o", "--output-dir", default="output")
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--all", action="store_true")
    return parser.parse_args()

def main():
    args = parse_args()

    # --all aktiviert alles
    tasks = [
        KerberoastAnalysis(), ASREPUserAnalysis(), AdminUserAnalysis(), SessionAnalysis(),
        EnabledUserAnalysis(), OldComputerAnalysis(), UnsupportedOSAnalysis(), NonWin10ProAnalysis(),
        DomainUserListAnalysis(), NeverChangedPasswordUsers(), InactiveUserAccounts(),
        NoPasswordRequiredUsers(), UsersWithLogonScript(), MultiGroupUsers()
    ] if args.all else []

    if not tasks:
        logging.warning("Keine Analyse ausgewählt (verwende z.B. --all)")
        sys.exit(0)

    parser = BloodHoundParser(args.input_dir, args.output_dir)
    parser.run_analysis(tasks, threads=args.threads)

if __name__ == "__main__":
    main()
