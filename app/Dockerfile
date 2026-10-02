# Node 12 reached end of life in April 2022 and gets no security fixes.
# Node 22 is a maintained LTS release.
FROM node:22-alpine
ENV WORKDIR /usr/src/app/
WORKDIR $WORKDIR
COPY package*.json $WORKDIR
# npm ci installs exactly what package-lock.json pins (no silent upgrades)
RUN npm ci --omit=dev --no-audit --no-fund

FROM node:22-alpine
ENV USER node
ENV WORKDIR /home/$USER/app
WORKDIR $WORKDIR
COPY --from=0 /usr/src/app/node_modules node_modules
RUN chown $USER:$USER $WORKDIR
COPY --chown=node . $WORKDIR
# In production environment uncomment the next line
#RUN chown -R $USER:$USER /home/$USER && chmod -R g-s,o-rx /home/$USER && chmod -R o-wrx $WORKDIR
# Then all further actions including running the containers should be done under non-root user.
USER $USER
EXPOSE 4000
