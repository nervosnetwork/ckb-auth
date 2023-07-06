
ROOT_PATH=$(cd "$(dirname "$0")";pwd)/../../

DOCKER_RIPPLED_NAME=rippled_$(uuidgen |sed 's/-//g')
RIPPLED_CONFIG_DIR=$ROOT_PATH/tools/rippled/config/

docker run -d -it --rm --name $DOCKER_RIPPLED_NAME -e ENV_ARGS="-a --start" -v $RIPPLED_CONFIG_DIR:/config/ xrpllabsofficial/xrpld:latest > /dev/null 2>&1

# docker run -it --rm -e ENV_ARGS="-a --start" -v $RIPPLED_CONFIG_DIR:/config/ xrpllabsofficial/xrpld:latest

echo $DOCKER_RIPPLED_NAME
