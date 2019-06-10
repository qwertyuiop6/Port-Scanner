import logging
import time


class log(object):
    def __init__(self, header, type):
        self.header = header
        self.type = type
        self.time = time.strftime("%Y-%m-%d[%H-%M]", time.localtime())
        self.filename = 'logs/%s-%s.log' % (type, self.time)
        logging.basicConfig(
            level=logging.DEBUG,
            format=
            '%(asctime)s - %(name)s- pid:[%(process)d] [%(thread)d]  %(levelname)s: %(message)s',
            filename=self.filename,
            filemode='a',
        )

    def show(self, msg):
        print(msg)
        logging.info('%s %s' % (self.header, msg))

    def err(self, msg):
        print('Error! ' + msg)
        logging.error(self.header + msg)

    def save(self, res):
        with open('logs/%s-res-%s.log' % (self.type, self.time), 'w') as t:
            t.write(res)


if __name__ == "__main__":
    l = log()
    l.show('test log')
