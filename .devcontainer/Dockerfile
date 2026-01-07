FROM ubuntu:rolling

RUN apt-get update && \
    apt-get install -y git curl && \
    su ubuntu sh -c 'curl -fsSL https://get.pnpm.io/install.sh | ENV="$HOME/.bashrc" SHELL="$(which bash)" bash -'
