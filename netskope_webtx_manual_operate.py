import json
import logging
import inspect
import base64
import hashlib
import hmac
import datetime

applogger = logging.getLogger()

import subprocess


def check_if_image_exists(image_name):
    try:
        subprocess.run(
            ["sudo", "docker", "image", "inspect", image_name], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        print("The docker image is already pulled in the system.")
        return True
    except subprocess.CalledProcessError:
        return False

def is_container_running(image_name):
    """Check if any container running the specified image is currently running."""
    # Execute 'docker ps' command and capture its output
    status = os.system("sudo docker ps | grep {}".format(image_name))
    # os.system returns 0 if the command was executed successfully
    return status == 0

def check_linux_distribution():
    # Execute the shell command to retrieve the Linux distribution information
    command = 'cat /etc/*-release | grep "PRETTY_NAME" | head -n 1'
    output_stream = os.popen(command)
    output = output_stream.read()
    
    # Parse the output to extract the distribution name
    distribution_info = output.split('=')[1].strip().strip('"')
    if "red" in distribution_info.lower():
        return "Red Hat"
    if "ubuntu" in distribution_info.lower():
        return "Ubuntu"
    if "cent" in distribution_info.lower():
        return "CentOs"
    return "Unknown"

def build_signature(
    workspace_id,
    workspace_key,
    date,
    content_length,
    method,
    content_type,
    resource,
):
    """To build signature which is required in header."""
    x_headers = "x-ms-date:" + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(workspace_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(workspace_id, encoded_hash)
    return authorization


def post_data_for_testing(workspace_id, workspace_key, body, log_type):
    """Build and send a request to the POST API.

    Args:
        body (str): Data to post into Sentinel log analytics workspace
        log_type (str): Custom log table name in which data wil be added.

    Returns:
        status_code: Returns the response status code got while posting data to sentinel.
    """
    __method_name = inspect.currentframe().f_code.co_name
    method = "POST"
    content_type = "application/json"
    resource = "/api/logs"
    rfc1123date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    content_length = len(body)
    try:
        signature = build_signature(
            workspace_id,
            workspace_key,
            rfc1123date,
            content_length,
            method,
            content_type,
            resource,
        )
    except Exception as err:
        applogger.error(
            "{}(method={}) : {} : Error occurred for build signature: {}".format(
                "WebTransactionsInitiate",
                __method_name,
                "NetskopeWebTx",
                err,
            )
        )
        raise Exception("Error while generating signature for posting data into log analytics.")
    uri = "https://" + workspace_id + ".ods.opinsights.azure.com" + resource + "?api-version=2016-04-01"

    headers = {
        "content-type": content_type,
        "Authorization": signature,
        "Log-Type": log_type,
        "x-ms-date": rfc1123date,
    }
    try:
        response = requests.post(uri, data=body, headers=headers)
        if response.status_code >= 200 and response.status_code <= 299:
            applogger.debug(
                "{}(method={}) : {} : Status_code: {} Accepted: Data Posted Successfully to azure sentinel.".format(
                    "WebTransactionsInitiate",
                    __method_name,
                    "NetskopeWebTx",
                    response.status_code,
                )
            )
            return response.status_code
        raise Exception(
            "Response code: {} from posting data to log analytics.\nError: {}".format(
                response.status_code, response.content
            )
        )
    except requests.exceptions.ConnectionError as id_error:
        applogger.error(
            "{}(method={}) : {} : Workspace ID is wrong: {}".format(
                "WebTransactionsInitiate",
                __method_name,
                "NetskopeWebTx",
                id_error,
            )
        )
        raise Exception()
    except Exception as nskp_err:
        applogger.error(
            "{}(method={}) : {} : NSKP Error: {}".format(
                "WebTransactionsInitiate",
                __method_name,
                "NetskopeWebTx",
                nskp_err,
            )
        )
        raise Exception("Exception: Error while posting data to sentinel.")


def verify_docker_installation():
    """Verify that docker engine is installed or not.

    Returns:
        bool: True if docker engine is installed and False if not installed.
    """
    try_starting_docker = os.system("sudo systemctl start docker")
    if try_starting_docker != 0:
        print("Docker is not installed on the system. Kindly Install Docker.")
        return False
    output = os.system("sudo docker ps")
    if output == 0:
        print("Docker Installation Verified Successfully")
        return True
    print("Docker is not Installed or not running, Kindly install docker and Run Again.")
    return False

def verify_pip_and_import_dependencies():
    global os
    import os
    global requests
    try:
        import requests
        print("Successfully imported Requests.")
    except ImportError:
        pip_verify = os.system("sudo pip3 install requests")
        if pip_verify != 0:
            print("pip3 is not installed, Trying to install pip3.")
            if check_linux_distribution() == "Ubuntu":
                install_pip = os.system("sudo apt install python3-pip")
                pip_verify = os.system("sudo pip3 install requests")
            elif check_linux_distribution() == "Red Hat" or check_linux_distribution() == "CentOs":
                install_pip = os.system("sudo yum install python3-pip")
                pip_verify = os.system("sudo pip3 install requests")
            else:
                print("Supported Linux Distributions for automatic pip3 installations are Red Hat, Centos and Ubuntu(Debian). Kindly Install pip3 manually.")
                print("Could not install requests library automatically, kindly install requests in python using pip3 and run again.")
                return False
        print("Installed requests module successfully.")
        import requests

    return True


def check_configuration_files_exist(configuration_files_list):
    """Check for the existence of the required configuration files and return the missing files.

    Args:
        configuration_files_list (list): list of the configuration files.

    Returns:
        list: list of missing files.
    """
    try:
        if not os.path.isdir("./docker_persistent_volume"):
            print("Docker Persistent Volume Directory does not Exist hence, Creating it.")
            os.system("sudo mkdir docker_persistent_volume")
        all_files = os.listdir("./docker_persistent_volume")
        all_files_set = set(all_files)
        configuration_files_set = set(configuration_files_list)
        missing_configuration_files_list = list(configuration_files_set - all_files_set)
        return missing_configuration_files_list
    except OSError as os_error:
        print("Error while performing operations on OS. Run Again. Error-{}.".format(os_error))


def verify_netskope_credentials(netskope_host_name, netskope_api_token):
    try:
        url = "https://{}/api/v2/events/token/transaction_events".format(netskope_host_name)
        print(url)
        print(netskope_api_token)
        headers = {"Netskope-Api-Token": netskope_api_token}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return True
        return False
    except Exception as err:
        print(err)
        return False


def save_environment_variables(file_name, env_variables):
    data_to_write = []
    for key, value in env_variables.items():
        data_to_write.append("{}={}\n".format(key, value))
    with open("./docker_persistent_volume/{}".format(file_name), "w") as f:
        f.writelines(data_to_write)


def verify_microsoft_sentinel_credentials(workspace_id, workspace_key):
    try:
        result = [{"status": "Credentials verified successfully."}]
        status = post_data_for_testing(workspace_id, workspace_key, json.dumps(result), "test_credentials")
        if status >= 200 and status <= 299:
            return True
        print("Sentinel Credentials were incorrect.")
        return False
    except Exception as error:
        print("Error occured while validating Sentinel Credentials!")
        print("Error: {}".format(error))
        return False


def take_missing_input(config_file_name):
    retry_count = 0
    if config_file_name == "netskope_config.env":
        print("Enter Netskope Credentials.")
        while retry_count < 3:
            netskope_host_name = input("Please Enter Netskope Hostname:")
            netskope_token = input("Please Enter Netskope Token:")
            if verify_netskope_credentials(netskope_host_name, netskope_token):
                print("Netskope Credentials Verified Successfully.")
                save_environment_variables(config_file_name, {"Hostname": netskope_host_name, "Token": netskope_token})
                print("Successfully saved the Netskope credentials.")
                return True
            print("Fetching Netskope Credentials Failed, Check Credentials and enter again.")
            retry_count += 1
        print("Retry Count Exceeded for validating Netskope Credentials, Kindly Run Again.")
        return False
    elif config_file_name == "sentinel_config.env":
        print("Enter Microsoft Sentinel Credentials.")
        while retry_count < 3:
            workspace_id = input("Please Enter the Workspace ID:")
            workspace_key = input("Please Enter the Workspace Key:")
            if verify_microsoft_sentinel_credentials(workspace_id, workspace_key):
                print("Sentinel Credentials Verified Successfully.")
                save_environment_variables(
                    config_file_name, {"WorkspaceId": workspace_id, "WorkspaceKey": workspace_key}
                )
                print("Successfully saved the Sentinel credentials.")
                return True
            print("Fetching Sentinel Credentials Failed, Check Credentials and enter again.")
            retry_count += 1
        print("Retry Count Exceeded for validating Sentinel Credentials, Kindly Run Again.")
        return False
    elif config_file_name == "general_config.env":
        print("Enter General Configuration.")
        while retry_count < 3:
            backoff_retry_count = input("Please Enter retry count for Pubsublite Verification failure(Example: 3) :")
            backoff_sleep_time = input("Please Enter the Sleep Time for Pubsublite Verification failure(Example: 60):")
            idle_timeout = input(
                "Please Enter the Time till which the subscriber will wait for messages before restarting(Example: 600): "
            )
            if backoff_retry_count == "" or backoff_sleep_time == "" or idle_timeout == "":
                print("You entered empty value in one of the parameters, Enter Again.")
                retry_count += 1
                continue
            save_environment_variables(
                config_file_name,
                {
                    "BackoffRetryCount": backoff_retry_count,
                    "BackoffSleepTime": backoff_sleep_time,
                    "IdleTimeout": idle_timeout,
                },
            )
            print("Successfully saved the General configuration.")
            return True
        print("Retry Count Exceeded for entering correct General Configuration, Kindly Run Again.")
        return False
    elif config_file_name == "seek_timestamp.env":
        seek_timestamp = input(
            "Please Enter a epoch timestamp if you want to seek the pubsublite cursor(Can be left empty):"
        )
        save_environment_variables(config_file_name, {"SeekTimestamp": seek_timestamp})
        print("Successfully saved the Seek Timestamp.")
        return True


def provide_docker_image_name():
    if not os.path.exists("docker_image_name"):
        docker_image_name = input("Enter the docker image name for WebTransactions:").strip()
        with open("docker_image_name", "w") as f:
            f.write(docker_image_name)
        return docker_image_name
    with open("docker_image_name", "r") as f:
        docker_image_name = f.read()
    return docker_image_name


def pull_docker_image(image_name):
    try:
        result = os.system("sudo docker pull {}".format(image_name))
        if result != 0:
            print("Error Occurred while pulling the docker image, please try again.")
            return False
        return True
    except OSError:
        print("Error Occurred while pulling the docker image.")


def edit_variable():
    while True:
        print("From the below options, Please enter the config that you want to change.")
        print("1. Press 1 to Edit Netskope Credentials.")
        print("2. Press 2 to Edit Microsoft Sentinel Credentials.")
        print("3. Press 3 to Edit General Configuration.")
        print("4. Press 4 to Edit/Add the Timetamp to seek cursor.")
        print("5. Press 5 to exit this menu and restart docker execution.")
        try:
            choice = int(input("Enter the choice from the above options: "))
            if choice == 1:
                os.system("sudo rm ./docker_persistent_volume/netskope_config.env")
                take_missing_input("netskope_config.env")
            elif choice == 2:
                os.system("sudo rm ./docker_persistent_volume/sentinel_config.env")
                take_missing_input("sentinel_config.env")
            elif choice == 3:
                os.system("sudo rm ./docker_persistent_volume/general_config.env")
                take_missing_input("general_config.env")
            elif choice == 4:
                os.system("sudo rm ./docker_persistent_volume/seek_timestamp.env")
                take_missing_input("seek_timestamp.env")
            elif choice == 5:
                print("You have chosen to exit the Edit Configuration Menu, Hence Exiting and starting docker again.")
                return
        except ValueError as val_error:
            print("You have provided wrong input, Please Enter a valid integer choice. Error-{}".format(val_error))
        except OSError:
            print(
                "There has been an error performing an OS operation, Kindly Troubleshoot and try again(Try running the python file as superuser)."
            )


def stop_docker_container(image_name):
    try:
        is_already_running = is_container_running(image_name)
        if not is_already_running:
            print("The container is not running!")
            return
        result = os.system("sudo docker stop $(sudo docker ps -q --filter ancestor={})".format(image_name))
        if result != 0:
            print("Error Occurred while stopping the docker image, please try again.")
    except OSError:
        print("Error Occurred while stopping the docker image.")


def start_docker_container(image_name):
    try:
        is_already_running = is_container_running(image_name)
        if is_already_running:
            print("The container is already running!")
            return
        result = os.system("sudo docker run -d -v $(pwd)/docker_persistent_volume:/app {}".format(image_name))
        if result != 0:
            print("Error Occurred while starting the docker image, please try again.")
    except OSError:
        print("Error Occurred while starting the docker image.")


def start_webtransactions():
    # Verify that docker engine is installed
    configuration_files_list = [
        "netskope_config.env",
        "sentinel_config.env",
        "general_config.env",
        "seek_timestamp.env",
    ]
    if not verify_pip_and_import_dependencies():
        return
    if not verify_docker_installation():
        return
    docker_image_name = provide_docker_image_name()
    if not check_if_image_exists(docker_image_name):
        print("Docker image does not exist, hence pulling.")
        if not pull_docker_image(docker_image_name):
            print("Issue pulling Docker image, edit docker image name")
            os.system("sudo rm docker_image_name")
            docker_image_name = provide_docker_image_name()
            print("The new docker image name is {}".format(docker_image_name))
            print("Pulling the new image.")
            if not pull_docker_image(docker_image_name):
                print("Issues pulling the docker image, please pull manually and try again.")
                return
            
    missing_files_list = check_configuration_files_exist(configuration_files_list)
    # Verify For Missing Parameters and enter them.
    if len(missing_files_list) > 0:
        print("{} configuration files are missing.".format(missing_files_list))
        for file in missing_files_list:
            if not take_missing_input(file):
                return

    print("Select Option from the menu that you want to perform.")
    while True:
        try:
            print("Enter the number from the below options.")
            print("1. Enter 1 to start the docker container.")
            print("2. Press 2 to stop the docker container.")
            print("3. Press 3 to edit any variable in the running execution.")
            print("4. Press 4 to pull and update the docker image.")
            print("5. Press 5 to change the docker image name.")
            print("6. Press 6 to Exit.")
            choice = int(input("Enter the input:"))
            if choice == 1:
                start_docker_container(docker_image_name)
            elif choice == 2:
                stop_docker_container(docker_image_name)
            elif choice == 3:
                print("You have selected to edit a variable, hence stopping execution first.")
                stop_docker_container(docker_image_name)
                edit_variable()
                start_docker_container(docker_image_name)
            elif choice == 4:
                print("You have selected to pull and update the docker image.")
                print("Stopping the running container if any.")
                stop_docker_container(docker_image_name)
                print("Pulling the image.")
                pull_docker_image(docker_image_name)
                print("Starting the docker image.")
                start_docker_container(docker_image_name)
            elif choice == 5:
                print("You have selected to edit the docker image name.")
                print("Stopping the running container if any.")
                stop_docker_container(docker_image_name)
                os.system("sudo rm docker_image_name")
                docker_image_name = provide_docker_image_name()
                print("The new docker image name is {}".format(docker_image_name))
                print("Pulling the new image.")
                pull_docker_image(docker_image_name)
                print("Starting the new docker image.")
                start_docker_container(docker_image_name)
                
            elif choice == 6:
                print("You have selected to exit, any previously executed commands will keep working, run again to perform any other operation.")
                break

        except ValueError:
            print("You have entered invalid input!!!")


if __name__ == "__main__":
    start_webtransactions()
