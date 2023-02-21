from sslyze import (
    ServerScanRequest,
    ServerNetworkLocation,
    ServerHostnameCouldNotBeResolved,
    Scanner,
    ServerScanStatusEnum,
    __version__ as sslyze_version
)
from sslyze.mozilla_tls_profile.mozilla_config_checker import (
    MozillaTlsConfigurationChecker,
    ServerNotCompliantWithMozillaTlsConfiguration,
    ServerScanResultIncomplete,
    MozillaTlsConfigurationEnum
)
import sys
import json
import time
import argparse

parser = argparse.ArgumentParser(
        prog = 'Sslyze compliance tool',
        description = "Scans host(s) with Sslyze and returns the compliance failures in a JSON format. This was required becuase Sslyze currently doesn't do this",
    )
parser.add_argument(
    '--hosts',
    required=True,
    nargs='+'
)
args = parser.parse_args()

def main() -> None:
    print("=> Starting the scans")

    try:
        all_scan_requests = []
        for hostname in args.hosts:
            all_scan_requests.append( ServerScanRequest(server_location=ServerNetworkLocation(hostname=hostname)) )
    except ServerHostnameCouldNotBeResolved:
        # Handle bad input ie. invalid hostnames
        print("Error resolving the supplied hostnames")
        sys.exit(1)

    # Then queue all the scans
    scanner = Scanner()
    scanner.queue_scans(all_scan_requests)
    
    mozilla_checker = MozillaTlsConfigurationChecker.get_default()
    are_all_servers_compliant = True

    compliance_failures = {
        'sslyze_version': sslyze_version.__version__,
        'datetime': time.strftime('%Y-%m-%d %X %Z'),
        'results': []
    }

    # And retrieve and process the results for each server
    all_server_scan_results = []
    for server_scan_result in scanner.get_results():
        all_server_scan_results.append(server_scan_result)

        target_hostname = server_scan_result.server_location.hostname

        # Were we able to connect to the server and run the scan?
        if server_scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            # No we weren't
            print(
                f"\nError: Could not connect to {target_hostname}:"
                f" {server_scan_result.connectivity_error_trace}"
            )
            continue

        # Since we were able to run the scan, scan_result is populated
        assert server_scan_result.scan_result

        print(
            f'Checking results for {target_hostname} against Mozilla\'s "modern"'
            f" configuration. See https://ssl-config.mozilla.org/ for more details.\n"
        )

        try:
            mozilla_checker.check_server(
                against_config=MozillaTlsConfigurationEnum( "modern" ),
                server_scan_result=server_scan_result,
            )
            print(f"    {server_scan_result.server_location.display_string}: OK - Compliant.\n")

        except ServerNotCompliantWithMozillaTlsConfiguration as e:
            are_all_servers_compliant = False
            findings = []
            print(f"    {server_scan_result.server_location.display_string}: FAILED - Not compliant.")
            for criteria, error_description in e.issues.items():
                findings.append( { 'criteria': criteria, 'issue_description': error_description } )
                print(f"        * {criteria}: {error_description}")
            print()
            compliance_failures['results'].append( {'hostname': target_hostname, 'findings': findings, 'errors': [] } )

        except ServerScanResultIncomplete as e:
            are_all_servers_compliant = False
            compliance_failures['results'].append( {'hostname': target_hostname, 'findings': [], 'errors': e } )
            print( f"{server_scan_result.server_location.display_string}: ERROR - Scan did not run successfully!" )

    with( open( '/tmp/sslyze-report.json', 'w' ) ) as report:
        report.write( json.dumps( compliance_failures ) )

    if not are_all_servers_compliant:
        # Return a non-zero error code to signal failure (for example to fail a CI/CD pipeline)
        sys.exit(1)



if __name__ == "__main__":
    main()

"""
{
    sslyze_version: "5.1.1",
    datetime: "2023-02-21 17:21:01 EST",
    results: [
        {
            hostname: "forwardsecurity.com",
            findings: [
                {
                    criteria: "tls_versions",
                    issue_description: "TLS versions {'TLSv1.2'} are supported, but should be rejected."
                },
                {...}
            ],
            errors: [
                "Could not connect...",
                ...
            ]
        },
        {...}
    ]
}
"""