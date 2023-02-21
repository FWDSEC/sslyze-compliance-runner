# Sslyze Compliance Runner

Runs Sslyze on the given host(s) and then drops a nice JSON file with what failed compliance testing.

## Usage
`docker run --rm -t -v $(pwd):/tmp sslyze-compliance-runner --hosts forwardsecurity.com facebook.com`

It drops an `sslyze-report.json` file in the mounted directory, and prints a human-friendly version to the screen.

Author: Jared Meit <j.meit@fwdsec.com>