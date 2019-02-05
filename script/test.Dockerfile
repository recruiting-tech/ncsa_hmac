FROM elixir:1.7-alpine

# Important!  Update this no-op ENV variable when this Dockerfile
# is updated with the current date. It will force refresh of all
# of the base images and things like `apt-get update` won't be using
# old cached versions when the Dockerfile is built.
ENV REFRESHED_AT=2019-02-05-1

RUN mkdir -p /opt/app
WORKDIR /opt/app

ADD ./ ./

RUN mix local.rebar --force
RUN mix local.hex --force
RUN MIX_ENV=test mix deps.get
CMD mix test
