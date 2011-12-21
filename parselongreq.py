#!/usr/bin/env python

import re
import datetime
import hashlib
import argparse

RE_SNIPPETS = {'iso-date': r'\d{4}-\d{2}-\d{2}',
               'iso-time': r'\d{2}:\d{2}:\d{2},\d{3}',
               'seconds': r'\d+\.\d+'}


def parse_date(str):
    return datetime.datetime.strptime(str, '%Y-%m-%d %H:%M:%S')


class Snapshot(object):

    # Time in request in seconds
    time = 0

    # Log lines attached to this snapshot
    info = ()
    def __init__(self, precision=7):
        self.info = []
        self.precision = precision

    def id(self):
        return hashlib.new('sha1', self.fingerprint()).hexdigest()[:8]

    def fingerprint(self):
        return ''.join(self.info[-self.precision:]).rstrip()


class Request(object):

    # Datetime when this request was started
    id = None
    started = None
    thread = None
    request = None

    def __init__(self, id):
        self.id = id
        self.snapshots = []

    @property
    def duration(self):
        return self.snapshots[-1].time


class LongRequestStatistics(object):

    header = re.compile(
        r'%(iso-date)s %(iso-time)s - Thread (?P<thread>-?\d+): Started on (?P<started>%(seconds)s); '
        r'Running for (?P<time>%(seconds)s) secs; request: (?P<request>.*)' % RE_SNIPPETS)

    def __init__(self, limit=10, precision=7,
                 start=datetime.datetime.min, end=datetime.datetime.max):
        self.limit = limit
        self.precision = precision
        self.requests = {}
        self.start = start
        self.end = end

    def parse(self, log):
        request = None
        for line in log:
            match = self.header.match(line)
            if not match:
                if request:
                    request.snapshots[-1].info.append(line)
                continue
            data = match.groupdict()
            req_id = (data['started'], data['thread'])
            if req_id not in self.requests:
                request = Request(req_id)
                request.thread = data['thread']
                request.started = datetime.datetime.fromtimestamp(float(data['started']))
                if not self.start <= request.started < self.end:
                    request = None
                    continue
                request.request = data['request']
                self.requests[req_id] = request
            else:
                request = self.requests[req_id]
            snapshot = Snapshot(self.precision)
            snapshot.time = float(data['time'])
            request.snapshots.append(snapshot)

    def report_requests(self):
        # Output 1: list all snapshots, aggregate by request
        requests_by_duration = sorted(self.requests.values(), key=lambda x:x.duration)
        requests_by_duration = reversed(requests_by_duration)
        print "=== Top %s long running requests ===" % self.limit
        for request in list(requests_by_duration)[:self.limit]:
            print request.started.strftime('%Y-%m-%d %H:%M:%S'), request.snapshots[-1].time, request.request
            for snapshot in request.snapshots:
                print "  %s" % snapshot.time, snapshot.id()
                print snapshot.fingerprint()
                print

    def report_snapshots(self):
        # Output 2: Give statistics about each fingerprint we found
        print "=== Top %s snapshots ===" % self.limit
        snapshots = {}
        for request in self.requests.values():
            for snapshot in request.snapshots:
                snapshots.setdefault(snapshot.id(), []).append(snapshot)

        topten_snapshots = sorted(snapshots, key=lambda s:len(snapshots[s]),
                                  reverse=True)[:10]

        total_snapshots = sum(len(s) for s in snapshots.values())
        topten_count = sum(len(snapshots[s]) for s in topten_snapshots)

        print "%s out of %s" % (topten_count, total_snapshots)

        for hash in topten_snapshots:
            print "%s - found %s times" % (hash , len(snapshots[hash]))
            print snapshots[hash][0].fingerprint()
            print



def main():
    parser = argparse.ArgumentParser(
        description='parse long request log')
    parser.add_argument(
        '--subject', choices=['requests', 'snapshots'],
        default='requests', help='What the subject of the statistics records should be.')
    parser.add_argument(
        '--limit', default=10, type=int,
        help='How many records should be displayed at most.')
    parser.add_argument(
        '--precision', default=7, type=int,
        help='Number of lines to use for fingerprinting tracebacks.')
    parser.add_argument(
        '--start', default=datetime.datetime.min, type=parse_date,
        help='earliest record to include')
    parser.add_argument(
        '--end', default=datetime.datetime.max, type=parse_date,
        help='latest record to include')
    parser.add_argument(
        'inputfile', type=argparse.FileType('r'),
        help='The log file that will be parsed.')
    args = parser.parse_args()
    stats = LongRequestStatistics(
        limit=args.limit,
        precision=args.precision,
        start=args.start,
        end=args.end)
    stats.parse(args.inputfile)
    getattr(stats, 'report_%s' % args.subject)()


if __name__ == '__main__':
    main()
