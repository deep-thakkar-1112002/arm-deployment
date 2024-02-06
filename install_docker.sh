echo "Hostname=$1" > "netskope_config.env"
echo "Token=$2" >> "netskope_config.env"
echo "WorkspaceKey=$3" >> "sentinel_config.env"
echo "WorkspaceId=$4" >> "sentinel_config.env"
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo docker pull deep1112002/netskopewebtransactions:nskpwebtransactions
