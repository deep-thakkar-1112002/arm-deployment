DATA_DIR="/home/devuser/docker_persistent_volume"
mkdir /home/devuser/docker_persistent_volume
echo "Hostname=$1" > "$DATA_DIR/netskope_config.env"
echo "Token=$2" >> "$DATA_DIR/netskope_config.env"
echo "WorkspaceKey=$3" >> "$DATA_DIR/sentinel_config.env"
echo "WorkspaceId=$4" >> "$DATA_DIR/sentinel_config.env"
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo docker pull deep1112002/netskopewebtransactions:nskpwebtransactions
