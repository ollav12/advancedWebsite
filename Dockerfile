FROM python:bullseye

RUN apt-get -y update && apt-get -y install tzdata less vim sqlite3 && apt-get clean && rm -rf /var/lib/apt/lists/* && rm -f /etc/localtime && ln -s /usr/share/zoneinfo/Europe/Oslo /etc/localtime && echo Europe/Oslo > /etc/timezone
#RUN pip install flask apsw pygments
RUN adduser --system headbook --group && ln -s /usr/local/bin/python /usr/bin/python
USER headbook
WORKDIR /home/headbook
ENV PATH=$PATH:/home/headbook/.local/bin
ADD --chown=headbook requirements.txt /home/headbook/
RUN pip install -r requirements.txt
ADD --chown=headbook . /home/headbook/
#RUN cd /home/headbook && git clone https://git.app.uib.no/inf226/23h/-server.git
#RUN python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
EXPOSE 5000
CMD ["flask", "-A", "headbook:app", "run", "-h", "0.0.0.0" ]
