FROM alpine AS build
RUN echo "hello world" > /tmp/hello.txt

FROM scratch
COPY --from=build /tmp/hello.txt /
