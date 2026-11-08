# Sources

* PortSwigger Academy — lab page (objective, required knowledge, badge EXPERT):
  https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-0cl-request-smuggling
* James Kettle, *HTTP/1.1 Must Die: the desync endgame* — the 0.CL section:
  https://portswigger.net/research/http1-must-die
  (0.CL deadlock, early-response gadgets, "moving beyond 400 Bad Request",
  double-desync, and the `POST /nul` + `HEAD` weaponisation examples)
* PortSwigger blog — *HTTP/1.1 Must Die: Conquering the 0.CL Challenge*:
  https://portswigger.net/blog/http-1-1-must-die-conquering-the-0-cl-challenge
* PortSwigger Academy — request smuggling topic (CL.TE / TE.CL / CL.0 basics,
  obfuscated header techniques):
  https://portswigger.net/web-security/request-smuggling
* Brandon T. Elliott — *Lab Writeup: PortSwigger "0.CL Request Smuggling"*
  (Turbo Intruder `examples/0cl-exploit.py` template, `/resources/css/...`
  gadget, stage-2 shape):
  https://brandon-t-elliott.github.io/0-cl-request-smuggling
* Nicolò Vinci — *0.CL PortSwigger Lab Solutions* (H-V probing with
  `Host :`/`Xost :`, early-response gadget, the two solution shapes):
  https://nicolovinci.com/posts/0cl/
* Observed behaviour of the live instance in this session (deadlock on
  `Content-Length : N`, `302` gadget, mystery `400`, in-band smuggled page):
  `evidence/desync-proof.txt`, `evidence/leaked-smuggled-page.html`,
  `logs/run-*.json`.
