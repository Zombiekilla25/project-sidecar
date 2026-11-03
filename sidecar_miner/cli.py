import argparse, json
from .config import Config

def main():
    p=argparse.ArgumentParser(prog="sidecar-miner",description="Offline-first Sidecar mining frontend")
    p.add_argument("--config")
    p.add_argument("--show-config",action="store_true",help="print non-secret configuration (wallet redacted)")
    a=p.parse_args(); c=Config.load(a.config)
    if a.show_config:
        print(json.dumps({"pool":c.pool,"wallet_configured":bool(c.wallet),"worker":c.worker,"mode":c.mode},sort_keys=True)); return 0
    print("sidecar-miner is an offline scaffold; live pool connections are disabled in this build")
    return 0
if __name__=="__main__": raise SystemExit(main())
