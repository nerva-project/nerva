# Using Nerva Docker Image

- Pull the official Nerva Docker image from Docker Hub:
    ```bash
    docker pull sn1f3rt/nerva
    ```

- Create network bridge so that containers can communicate.
    ```bash
    docker network create --driver bridge nerva
    ```

- Start the daemon.
    ```bash
    docker run -d --rm --name nerva-daemon \
    --net=nerva \
    -v daemon:/data \
    -p 17565:17565 \
    -p 17566:17566 \
    sn1f3rt/nerva \
    nervad \
    --data-dir=/data \
    --confirm-external-bind \
    --non-interactive
    ```

- Start the CLI wallet.
    ```bash
    docker run --rm -it --name nerva-wallet \
    --net=nerva \
    -v wallet:/data \
    sn1f3rt/nerva \
    nerva-wallet-cli \
    --trusted-daemon \
    --daemon-address nerva-daemon:17566
    ```
