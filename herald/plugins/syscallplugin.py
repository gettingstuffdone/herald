#!/usr/bin/env python
# -*- coding: utf-8 -*-

import math
import psutil
import time

from herald.baseplugin import HeraldPlugin


def time_in_ms():
    return math.floor(time.time() * 1000)


class DeltaMeter(object):
    """
    DeltaMeter provides an easy way to compute metric increments.
    """

    def __init__(self, init_value=0):
        self.last_update = time_in_ms()
        self.last = init_value

    def update_and_get(self, value):
        v = value
        delta = abs(v - self.last)
        self.last = v
        return delta


class SimpleMeter(object):
    """
    SimpleMeter is a simple typed meter. You can use it when you need cast a string -> my_type
    """

    def __init__(self, _type, init_value):
        self.last_update = time_in_ms()
        self.last = _type(init_value)
        self.type = _type

    def update_and_get(self, value):
        self.last = self.type(value)
        return self.last


class SyscallPlugin(HeraldPlugin):
    """
    Reads state from the syscall. If `is_json` is set file
    contents are parsed using json.

    """

    herald_plugin_name = 'herald_syscall'

    def __init__(self, *args, **kwargs):
        super(SyscallPlugin, self).__init__(*args, **kwargs)

        self.nic = kwargs.get('nic', None)
        self.nic_speed = kwargs.get('nic_speed', None)
        self.available_mem_thd = kwargs.get('available_memory_thd', 1000000000)
        self.interval = kwargs.get('interval', 5)
        self.userate_thd = kwargs.get('userate_thd', 10)
        self.paths = []
        self.io_data = None
        self.cpu_percent_data = 0.0
        self.net_percent_data = 0.0
        self.paths_data = None
        self.mem_virtual_data = None
        self.mem_swap_data = None
        self.io_disk_data = None

        self.measures = {}
        self.__collect__()
        self.__register__()

    def run(self):
        try:
            self.logger.debug('Start collect statistics ...')
            self.__collect__()
            data = self.__process__()
            self.logger.debug(
                'Statistics: \'health\': {}, \'use-rate\': {:.2f}%'.
                    format(data['health'], data['use-rate']))
        except IOError as e:
            self.logger.critical('could not read file, error: %s' % str(e))
            return

        return data

    def __str__(self):
        return self.name

    def __unicode__(self):
        return self.name

    def __process__(self):
        cpu_data = self.measures["cpu"].update_and_get(self.cpu_percent_data)
        mem_data = {
            "virtual": {
                "total": self.measures["mem.virtual.total"].update_and_get(self.mem_virtual_data.total),
                "available": self.measures["mem.virtual.available"].update_and_get(self.mem_virtual_data.available),
                "percent": self.measures["mem.virtual.percent"].update_and_get(self.mem_virtual_data.percent),
                "used": self.measures["mem.virtual.used"].update_and_get(self.mem_virtual_data.used),
                "free": self.measures["mem.virtual.free"].update_and_get(self.mem_virtual_data.free),
                "active": self.measures["mem.virtual.active"].update_and_get(self.mem_virtual_data.active),
                "inactive": self.measures["mem.virtual.inactive"].update_and_get(self.mem_virtual_data.inactive),
                # "buffers": self.measures["mem.virtual.buffers"].update_and_get(self.mem_virtual_data.buffers),
                # "cached": self.measures["mem.virtual.cached"].update_and_get(self.mem_virtual_data.cached),
            },
            "swap": {
                "total": self.measures["mem.swap.total"].update_and_get(self.mem_swap_data.total),
                "used": self.measures["mem.swap.used"].update_and_get(self.mem_swap_data.used),
                "free": self.measures["mem.swap.free"].update_and_get(self.mem_swap_data.free),
                "percent": self.measures["mem.swap.percent"].update_and_get(self.mem_swap_data.percent),
                "sin": self.measures["mem.swap.sin"].update_and_get(self.mem_swap_data.sin),
                "sout": self.measures["mem.swap.sout"].update_and_get(self.mem_swap_data.sout),
            }
        }

        if self.nic in self.io_data:
            network_data = {
                "name"        : self.nic,
                "bytes_sent"  : self.measures[self.nic + ".bytes_sent"].update_and_get(self.io_data[self.nic].bytes_sent),
                "bytes_recv"  : self.measures[self.nic + ".bytes_recv"].update_and_get(self.io_data[self.nic].bytes_recv),
                "packets_sent": self.measures[self.nic + ".packets_sent"].update_and_get(self.io_data[self.nic].packets_sent),
                "packets_recv": self.measures[self.nic + ".packets_recv"].update_and_get(self.io_data[self.nic].packets_recv),
                "errin"       : self.measures[self.nic + ".errin"].update_and_get(self.io_data[self.nic].errin),
                "errout"      : self.measures[self.nic + ".errout"].update_and_get(self.io_data[self.nic].errout),
                "dropin"      : self.measures[self.nic + ".dropin"].update_and_get(self.io_data[self.nic].dropin),
                "dropout"     : self.measures[self.nic + ".dropout"].update_and_get(self.io_data[self.nic].dropout),
            }
        else:
            network_data = {}

        paths = []
        for idx, p in enumerate(self.paths):
            current_path = self.paths[idx]
            current_path_data = self.paths_data[idx]

            path_name = current_path["name"]
            path = current_path["path"]
            paths.append({
                "name"   : path_name,
                "path"   : path,
                "total"  : self.measures[path_name + ".total"].update_and_get(current_path_data.total),
                "used"   : self.measures[path_name + ".used"].update_and_get(current_path_data.used),
                "free"   : self.measures[path_name + ".free"].update_and_get(current_path_data.free),
                "percent": self.measures[path_name + ".percent"].update_and_get(current_path_data.percent)
            })

        io_disks = [{
            "disk_id"    : k,
            "read_count" : self.measures[k + ".read_count"].update_and_get(self.io_disk_data[k].read_count),
            "write_count": self.measures[k + ".write_count"].update_and_get(self.io_disk_data[k].write_count),
            "read_bytes" : self.measures[k + ".read_bytes"].update_and_get(self.io_disk_data[k].read_bytes),
            "write_bytes": self.measures[k + ".write_bytes"].update_and_get(self.io_disk_data[k].write_bytes),
            "read_time"  : self.measures[k + ".read_time"].update_and_get(self.io_disk_data[k].read_time),
            "write_time" : self.measures[k + ".write_time"].update_and_get(self.io_disk_data[k].write_time)
        } for k in self.io_disk_data]

        messages = {
            "cpu": cpu_data,
            "mem": mem_data,
            "io_disks": [{"io_disk": io_disk} for io_disk in io_disks],
            "paths": [{"disk": path} for path in paths],
            "networks": network_data,
        }

        self.logger.debug('Load: {}'.format(messages))
        free_mem = mem_data['virtual']['available']
        if free_mem < self.available_mem_thd:
            self.logger.fatal('Out of memory. Only {} bytes left!'.
                              format(free_mem))
            health_status = 'unhealthy'
        else:
            health_status = 'healthy'

        network_usage = network_data.get("bytes_sent", 0) * 100 * 8 \
                        / self.interval / self.nic_speed
        if network_usage > self.userate_thd:
            self.logger.info('Network io used {:.2f}%'.format(network_usage))
        if self.cpu_percent_data > self.userate_thd:
            self.logger.info('Cpu usage {:.2f}%'.format(self.cpu_percent_data))

        self.net_percent_data = self.net_percent_data * 0.7 + network_usage * 0.3

        return {'health': health_status, 'use-rate': max(cpu_data, self.net_percent_data)}

    def __collect__(self):
        self.io_data = psutil.net_io_counters(pernic=True)
        self.cpu_percent_data = self.cpu_percent_data * 0.7 + psutil.cpu_percent(interval=None) * 0.3
        self.mem_virtual_data = psutil.virtual_memory()
        self.mem_swap_data = psutil.swap_memory()
        self.paths_data = [psutil.disk_usage(p["path"]) for p in self.paths]
        self.io_disk_data = psutil.disk_io_counters(perdisk=True)

    def __register__(self):
        network_interfaces = [ni for ni in psutil.net_io_counters(pernic=True)]
        for network_interface in network_interfaces:
            self.measures[network_interface + ".bytes_sent"]   = DeltaMeter(self.io_data[network_interface].bytes_sent)
            self.measures[network_interface + ".bytes_recv"]   = DeltaMeter(self.io_data[network_interface].bytes_recv)
            self.measures[network_interface + ".packets_sent"] = DeltaMeter(self.io_data[network_interface].packets_sent)
            self.measures[network_interface + ".packets_recv"] = DeltaMeter(self.io_data[network_interface].packets_recv)
            self.measures[network_interface + ".errin"]        = DeltaMeter(self.io_data[network_interface].errin)
            self.measures[network_interface + ".errout"]       = DeltaMeter(self.io_data[network_interface].errout)
            self.measures[network_interface + ".dropin"]       = DeltaMeter(self.io_data[network_interface].dropin)
            self.measures[network_interface + ".dropout"]      = DeltaMeter(self.io_data[network_interface].dropout)

        self.measures["cpu"]                   = SimpleMeter(float, self.cpu_percent_data)
        self.measures["mem.virtual.total"]     = SimpleMeter(int, self.mem_virtual_data.total)
        self.measures["mem.virtual.available"] = SimpleMeter(int, self.mem_virtual_data.available)
        self.measures["mem.virtual.percent"]   = SimpleMeter(float, self.mem_virtual_data.percent)
        self.measures["mem.virtual.used"]      = SimpleMeter(int, self.mem_virtual_data.used)
        self.measures["mem.virtual.free"]      = SimpleMeter(int, self.mem_virtual_data.free)
        self.measures["mem.virtual.active"]    = SimpleMeter(int, self.mem_virtual_data.active)
        self.measures["mem.virtual.inactive"]  = SimpleMeter(int, self.mem_virtual_data.inactive)
        # self.measures["mem.virtual.buffers"]   = SimpleMeter(int, self.mem_virtual_data.buffers)
        # self.measures["mem.virtual.cached"]    = SimpleMeter(int, self.mem_virtual_data.cached)
        self.measures["mem.swap.total"]        = SimpleMeter(int, self.mem_swap_data.total)
        self.measures["mem.swap.used"]         = SimpleMeter(int, self.mem_swap_data.used)
        self.measures["mem.swap.free"]         = SimpleMeter(int, self.mem_swap_data.free)
        self.measures["mem.swap.percent"]      = SimpleMeter(float, self.mem_swap_data.percent)
        self.measures["mem.swap.sin"]          = SimpleMeter(int, self.mem_swap_data.sin)
        self.measures["mem.swap.sout"]         = SimpleMeter(int, self.mem_swap_data.sout)

        disks = [disk for disk in psutil.disk_io_counters(perdisk=True)]
        for disk in disks:
            self.measures[disk + ".read_count"]  = DeltaMeter(self.io_disk_data[disk].read_count)
            self.measures[disk + ".write_count"] = DeltaMeter(self.io_disk_data[disk].write_count)
            self.measures[disk + ".read_bytes"]  = DeltaMeter(self.io_disk_data[disk].read_bytes)
            self.measures[disk + ".write_bytes"] = DeltaMeter(self.io_disk_data[disk].write_bytes)
            self.measures[disk + ".read_time"]   = DeltaMeter(self.io_disk_data[disk].read_time)
            self.measures[disk + ".write_time"]  = DeltaMeter(self.io_disk_data[disk].write_time)

        for idx, path_data in enumerate(self.paths_data):
            path = self.paths[idx]
            path_name = path["name"]
            path_data = psutil.disk_usage(path["path"])
            self.measures[path_name + ".total"]   = SimpleMeter(int, path_data.total)
            self.measures[path_name + ".used"]    = SimpleMeter(int, path_data.used)
            self.measures[path_name + ".free"]    = SimpleMeter(int, path_data.free)
            self.measures[path_name + ".percent"] = SimpleMeter(float, path_data.percent)

