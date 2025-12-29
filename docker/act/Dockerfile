FROM alpine:3.23

RUN apk add --no-cache bash curl docker git

RUN curl -s https://raw.githubusercontent.com/nektos/act/master/install.sh | bash

ENTRYPOINT ["act"]
