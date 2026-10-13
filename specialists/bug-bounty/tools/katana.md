# katana

Purpose: crawl web applications to discover routes, forms, parameters, and JavaScript references.

Runtime note: the wowbagger sandbox wraps ProjectDiscovery tools with `-duc` to disable update checks.

## Syntax

```bash
katana -u http://target:8000 -d 2 -silent
katana -u http://target:8000 -jc -kf all -d 3 -silent
katana -list urls.txt -d 2 -silent -o katana-routes.txt
```

## Use Rules

- Keep crawl depth low until the app shape is known.
- Save discovered URLs.
- Review JavaScript links manually before fuzzing.
