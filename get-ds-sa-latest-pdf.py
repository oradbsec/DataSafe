# Demonstrates the use of the Data Safe Python APIs to get all Security Assessments report PDFs for all database targets in all OCI regions.

import sys
import configparser
import os
import argparse
import oci
import json
import time

try:
    import datasafe_python_client.datasafe_spec.models as data_safe_models
    from datasafe_python_client.datasafe_spec import DataSafeClient, DataSafeClientCompositeOperations
except ImportError:
    import oci.data_safe.models as data_safe_models
    from oci.data_safe import DataSafeClient, DataSafeClientCompositeOperations

class Target:
    def __init__(self, target_id):
        self.target_id = target_id

class Tenancy:
    def __init__(self, tenancy_id):
        self.tenancy_id = tenancy_id
        self.targets = []

    def add_target(self, target_summary):
        self.targets.append(target_summary)

def get_oci_profile_names(config_file_path):
    config_file_path = os.path.expanduser(config_file_path)
    config_parser = configparser.ConfigParser()
    config_parser.read(config_file_path)
    profile_names = config_parser.sections()
    return profile_names

def check_work_request_status(wr_client, work_request_id):
    work_request_response = wr_client.get_work_request(work_request_id)
    return work_request_response.data.status

def read_data_from_tenancies(config_file_path, profile):
    try:
        oci_config = oci.config.from_file(config_file_path, profile_name=profile)
        data_safe_client = DataSafeClient(oci_config)
        tenancy_name = oci_config.get('tenancy')
        tenancy_obj = Tenancy(tenancy_id=tenancy_name)
    except (oci.exceptions.ConfigFileNotFound, oci.exceptions.InvalidConfig, configparser.Error) as e:
        print(f"Error reading OCI config file for profile {profile}: {e}")
        return

    try:
        list_security_assessments_response = data_safe_client.list_security_assessments(
            compartment_id=tenancy_name,
            type="LATEST",
            lifecycle_state="SUCCEEDED",
            compartment_id_in_subtree=True,
            access_level="ACCESSIBLE"
        )
    except oci.exceptions.ServiceError as e:
        print(f"Error listing security assessments: {e}")
        return

    work_requests = []

    for instance in list_security_assessments_response.data:
        target_id = instance.target_ids[0]
        target_obj = Target(target_id)
        tenancy_obj.add_target(target_obj)

        try:
            generate_security_assessment_report_response = data_safe_client.generate_security_assessment_report(
                 security_assessment_id=instance.id,
                 generate_security_assessment_report_details=oci.data_safe.models.GenerateSecurityAssessmentReportDetails(format="PDF")
            )   
        except oci.exceptions.ServiceError as e:
            print(f"Error generating security assessment report for {instance.id}: {e}")
            continue

        opc_work_request_id = generate_security_assessment_report_response.headers.get('opc-work-request-id')
        print(f"OPC Work Request ID: {opc_work_request_id}")
        work_requests.append((instance.id, opc_work_request_id))

    print("All reports generation requests sent. Waiting for 30 seconds...")
    time.sleep(30)

    all_succeeded = False

    while not all_succeeded:
        all_succeeded = True
        for instance_id, opc_work_request_id in work_requests:
            work_request_status = check_work_request_status(data_safe_client, opc_work_request_id)
            print(f"Work request status for {instance_id}: {work_request_status}")
            if work_request_status != 'SUCCEEDED':
                all_succeeded = False
                if work_request_status == 'FAILED':
                    print(f"Work request for {instance_id} failed.")
                break
        if not all_succeeded:
            print("Not all work requests succeeded. Waiting for 30 more seconds...")
            time.sleep(30)

    for instance_id, _ in work_requests:
        try:
            download_security_assessment_report_response = data_safe_client.download_security_assessment_report(
                 security_assessment_id=instance_id,
                 download_security_assessment_report_details=oci.data_safe.models.DownloadSecurityAssessmentReportDetails(format="PDF")
            )
        except oci.exceptions.ServiceError as e:
            print(f"Error downloading security assessment report for {instance_id}: {e}")
            continue

        report_content = download_security_assessment_report_response.data.content
        report_filename = f"{profile}_{instance_id}_security_assessment_report.pdf"
        with open(report_filename, 'wb') as file:
            file.write(report_content)
        print(f"Security assessment report for {profile} downloaded successfully as {report_filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read OCI Profile Names from Configuration File")

    parser.add_argument(
        "--f",
        dest="config_file_path",
        default="~/.oci/config",
        help="Path to the OCI configuration file (default: ~/.oci/config). This file contains the credentials and settings for different OCI profiles."
    )

    parser.add_argument(
        "--profile",
        dest="profile_names",
        nargs="*",
        default=[],
        help="OCI profile names to retrieve. Provide a space-separated list. If not specified, all profiles from the configuration file will be considered."
    )

    args = parser.parse_args()
    if args.profile_names:
        print("OCI Profile Names:", args.profile_names)
        oci_profiles = args.profile_names
    else:
        oci_profiles = get_oci_profile_names(args.config_file_path)
        if oci_profiles:
            print("OCI Profile Names:", oci_profiles)
        else:
            print("No OCI config with Profile Names found.")

    for profile in oci_profiles:
        read_data_from_tenancies(args.config_file_path, profile)
