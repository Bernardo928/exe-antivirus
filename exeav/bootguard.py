"""Proteção ao ligar o computador.

Toda vez que o computador liga (uma vez por inicialização):

1. os bloqueios do firewall são reaplicados (regras do nftables/iptables somem ao reiniciar);
2. cada programa que inicia junto com o sistema é avaliado:
     - vírus ou comando suspeito                  → bloqueado sempre;
     - programa liberado por você                 → liberado;
     - item do sistema operacional                → liberado;
     - modo "desconhecidos" (padrão): programas assinados digitalmente (Windows) ou instalados pelo
       gerenciador de pacotes (Linux) são liberados; o resto é bloqueado;
     - modo "todos": tudo o que não é do sistema e não foi liberado por você é bloqueado;
     - modo "avisar": nada é bloqueado, só avisa.
   Bloquear = encerrar o programa que acabou de abrir, cortar a internet dele no firewall e tirá-lo da
   inicialização (com cópia de segurança: "Liberar" desfaz tudo);
3. depois de alguns segundos, um scan rápido roda em segundo plano com prioridade baixa.

Enquanto o antivírus está aberto, a inicialização também é vigiada: um item novo (o jeito como vírus
garantem que voltam depois de reiniciar) passa pela mesma avaliação na hora.
"""
from __future__ import annotations

import os
import threading
import time

import psutil

from . import firewall, history, paths
from .engine.models import MALICIOUS
from .system import startup

LIBERADO, BLOQUEADO, AVISO = "liberado", "bloqueado", "aviso"


def item_key(it: dict) -> str:
    return f"{it.get('source')}|{it.get('name')}|{it.get('location')}"


def _is_system_target(path: str) -> bool:
    if not path:
        return False
    n = paths.norm(path)
    if paths.IS_WINDOWS:
        sysroot = paths.norm(os.environ.get("SystemRoot", r"C:\Windows"))
        return n.startswith(sysroot + os.sep)
    return n.startswith(("/usr/", "/bin/", "/sbin/", "/lib/")) and not n.startswith("/usr/local/")


def _boot_time() -> float:
    try:
        return float(psutil.boot_time())
    except Exception:
        return 0.0


class Decision(dict):
    """{'item', 'key', 'decision', 'reason', 'trusted', 'verdict', 'threat'}"""


class BootGuard:
    """callback(evento, dados): 'decision' (Decision), 'blocked' (Decision), 'boot_scan' (str: 'start'/'done'),
    'threat' (ScanResult), 'status' (str)."""

    def __init__(self, engine, quarantine, callback=None, cache=None, lister=None, watch_interval: float = 300):
        self.engine = engine
        self.settings = engine.settings
        self.quarantine = quarantine
        self.callback = callback or (lambda *a: None)
        self.cache = cache
        self.lister = lister or startup.list_items
        self.watch_interval = watch_interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._known: set[str] = set()
        self.last: list[Decision] = []
        self.blocked_this_boot = 0
        self.boot_scan_state = ""
        self.scanner = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop.is_set()

    # ------------------------------------------------------------------ avaliação
    def classify(self, items: list[dict]) -> list[Decision]:
        out = []
        mode = self.settings.boot_block_mode
        policy = self.settings.startup_policy
        excl = self.engine.exclusions
        from .engine import trust
        for it in items:
            key = item_key(it)
            target = it.get("target") or ""
            d = Decision(item=it, key=key, decision=LIBERADO, reason="", trusted=False, verdict="", threat="")
            if target and excl.is_excluded(target):
                d["reason"] = "o próprio antivírus"
                out.append(d)
                continue
            res = None
            if target and os.path.isfile(target):
                try:
                    res = self.engine.scan_file(target).result
                except Exception:
                    res = None
                try:
                    d["trusted"] = trust.check(target)[0]
                except Exception:
                    d["trusted"] = False
            if res is not None:
                d["verdict"], d["threat"] = res.verdict, res.threat_name
                d["_result"] = res
            user = policy.get(key)
            system = _is_system_target(target) and d["trusted"]
            if res is not None and res.verdict == MALICIOUS:
                d["decision"], d["reason"] = (AVISO, "vírus — mas foi liberado por você") if user == LIBERADO \
                    else (BLOQUEADO, f"vírus: {res.threat_name}")
            elif user == LIBERADO:
                d["reason"] = "liberado por você"
            elif user == BLOQUEADO:
                d["decision"], d["reason"] = BLOQUEADO, "bloqueado por você"
            elif it.get("suspicious") or (res is not None and res.is_threat):
                d["decision"] = BLOQUEADO
                d["reason"] = f"suspeito: {res.threat_name}" if res is not None and res.is_threat else \
                    "comando suspeito (oculto, codificado ou em pasta temporária)"
            elif not it.get("removable", True) or it.get("kind") in ("preload", "shellrc"):
                d["reason"] = "item do sistema (não pode ser bloqueado automaticamente)"
            elif system:
                d["reason"] = "programa do sistema operacional"
            elif mode == "todos":
                d["decision"], d["reason"] = BLOQUEADO, "modo bloquear todos: não foi liberado por você"
            elif d["trusted"]:
                d["reason"] = "assinado digitalmente" if paths.IS_WINDOWS else "instalado pelo gerenciador de pacotes"
            else:
                d["decision"] = BLOQUEADO
                d["reason"] = "programa desconhecido (sem assinatura digital)" if target else \
                    "comando sem programa identificável"
            if mode == "avisar" and d["decision"] == BLOQUEADO:
                d["decision"] = AVISO
            out.append(d)
        return out

    # ------------------------------------------------------------------ ações
    def _kill_running(self, target: str) -> int:
        if not target:
            return 0
        from .realtime import _self_and_ancestors
        from .system import processes
        protected = _self_and_ancestors()
        want = paths.norm(target)
        n = 0
        for p in psutil.process_iter(["pid", "exe", "cmdline"]):
            try:
                exe = p.info["exe"] or ""
                cmd = p.info["cmdline"] or []
                hit = (exe and paths.norm(exe) == want) or any(
                    a and os.path.isabs(a) and paths.norm(a) == want for a in cmd[1:6])
                if not hit or p.pid in protected or processes.critical_reason(p.pid):
                    continue
                processes.kill(p.pid)
                n += 1
            except (psutil.Error, OSError):
                continue
        return n

    def block(self, d: Decision, remember: bool = False) -> str:
        """Bloqueia um item; retorna o resumo das ações."""
        it = d["item"]
        target = it.get("target") or ""
        acts = []
        killed = self._kill_running(target)
        if killed:
            acts.append(f"{killed} processo(s) encerrado(s)")
        res = d.get("_result")
        if res is not None and res.verdict == MALICIOUS and self.settings.auto_action == "quarantine":
            try:
                self.quarantine.isolate(res)
                acts.append("arquivo em quarentena")
            except Exception:
                pass
        if target and os.path.exists(target) and firewall.app_backend():
            try:
                firewall.block_app(target, f"inicialização bloqueada: {d.get('reason', '')}")
                acts.append("internet bloqueada no firewall")
            except Exception:
                pass
        if it.get("removable", True):
            try:
                startup.disable_item(it)
                acts.append("removido da inicialização")
            except Exception as e:
                acts.append(f"não foi possível tirar da inicialização ({e})")
        if remember:
            self.settings.startup_policy[d["key"]] = BLOQUEADO
            self._save()
        summary = ", ".join(acts) or "nenhuma ação possível"
        d["action"] = summary
        history.log("inicialização", f"Bloqueado ao ligar: {it.get('name')} — {d.get('reason', '')} ({summary})",
                    target or it.get("location", ""))
        self.blocked_this_boot += 1
        self.callback("blocked", d)
        return summary

    def allow(self, key: str, record_id: str | None = None, target: str = "") -> None:
        """Libera um item: volta para a inicialização, desbloqueia no firewall e lembra a escolha."""
        if record_id:
            startup.restore_item(record_id)
        if target and target in firewall.blocked_apps():
            try:
                firewall.unblock_app(target)
            except Exception:
                pass
        self.settings.startup_policy[key] = LIBERADO
        self._save()

    def _save(self) -> None:
        from . import config
        try:
            config.save()
        except OSError:
            pass

    def enforce(self, decisions: list[Decision]) -> int:
        n = 0
        for d in decisions:
            self.callback("decision", d)
            if d["decision"] == BLOQUEADO:
                self.block(d)
                n += 1
            elif d["decision"] == AVISO:
                history.log("inicialização", f"Aviso: {d['item'].get('name')} — {d['reason']}",
                            d["item"].get("target") or "")
        return n

    def check_now(self) -> list[Decision]:
        items = self.lister()
        self._known = {item_key(i) for i in items}
        decisions = self.classify(items)
        self.enforce(decisions)
        self.last = decisions
        return decisions

    # ------------------------------------------------------------------ ciclo
    def is_new_boot(self) -> bool:
        bt = _boot_time()
        return bt > 0 and bt > float(self.settings.last_boot_handled or 0) + 1

    def on_boot(self, force: bool = False, scan_delay: float | None = None) -> bool:
        """Executa as tarefas de inicialização (uma vez por boot). Retorna True se executou."""
        if not (force or self.is_new_boot()):
            return False
        self.settings.last_boot_handled = _boot_time() or time.time()
        self._save()
        try:
            n = firewall.reapply()
            if n:
                history.log("firewall", f"{n} bloqueio(s) do firewall reaplicado(s) ao ligar o computador")
        except Exception:
            pass
        history.log("inicialização", "Proteção ao ligar: verificando os programas que iniciam com o sistema")
        self.check_now()
        if self.settings.boot_scan:
            delay = self.settings.boot_scan_delay if scan_delay is None else scan_delay
            threading.Thread(target=self._boot_scan, args=(delay,), daemon=True, name="boot-scan").start()
        return True

    def _boot_scan(self, delay: float) -> None:
        if self._stop.wait(delay):
            return
        from .scanner import BOOT, Scanner, quick_targets
        self.boot_scan_state = "rodando"
        self.callback("boot_scan", "start")

        def on_threat(r):
            if r.verdict == MALICIOUS and self.settings.auto_action == "quarantine":
                try:
                    self.quarantine.isolate(r)
                    r.action = "quarentena"
                except Exception as e:
                    r.action = f"falha ao isolar: {e}"
            else:
                r.action = "notificado"
            self.callback("threat", r)
        self.scanner = Scanner(self.engine, BOOT, quick_targets(), on_threat=on_threat, cache=self.cache,
                               low_priority=True)
        st = self.scanner.run()
        self.boot_scan_state = f"concluído: {st.files} arquivos, {len(st.threats)} ameaça(s)"
        self.scanner = None
        self.callback("boot_scan", "done")

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="boot-guard")
        self._thread.start()
        self.callback("status", "on")

    def stop(self) -> None:
        self._stop.set()
        if self.scanner is not None:
            self.scanner.stop()
        if self._thread:
            self._thread.join(timeout=5)
        self._thread = None
        self.callback("status", "off")

    def _loop(self) -> None:
        try:
            if not self.on_boot():
                self._known = {item_key(i) for i in self.lister()}
        except Exception:
            pass
        while not self._stop.wait(self.watch_interval):
            try:
                self.watch_once()
            except Exception:
                continue

    def watch_once(self) -> list[Decision]:
        """Avalia só os itens que apareceram na inicialização desde a última leitura."""
        items = self.lister()
        new = [i for i in items if item_key(i) not in self._known]
        self._known = {item_key(i) for i in items}
        if not new:
            return []
        for i in new:
            history.log("inicialização", f"Novo item de inicialização: {i.get('name')} ({i.get('source')})",
                        i.get("command", ""))
        decisions = self.classify(new)
        self.enforce(decisions)
        self.last = [d for d in self.last if d["key"] not in {x["key"] for x in decisions}] + decisions
        return decisions
