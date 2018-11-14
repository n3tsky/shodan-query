# Shodan-query

A really simple shodan parser for any given IP address (or file).
Nothing new, probably a ton of other scripts doing the same job.

Do not forget to add the "API_KEY" in the script 

* For a single host
```
python shodan-query.py -i X.X.X.X 
```

* For a list of hosts
```
python shodan-query.py -f ips.txt
```

* For a list of hosts (+ wait X seconds between each request)
```
python shodan-query.py -f ips.txt -t X
```

* Get more info (verbosity) 
```
python shodan-query.py -f ips.txt -v
```

## Requirements

- shodan
- argparse
- json
