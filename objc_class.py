
import idaapi, idautils, idc
import re

encoded_types = {
  'c':'char',
  'i':'int',
  's':'short',
  'l':'long',
  'q':'long long',
  'C':'unsigned char',
  'I':'unsigned int',
  'S':'unsigned short',
  'L':'unsigned long',
  'Q':'unsigned long long',
  'f':'float',
  'd':'double',
  'B':'bool',
  'v':'void',
  '*':'char *',
  '@':'id',
  '#':'class',
  '?':'unknown',
  ':':'SEL',
  '^':'ptr'}

class ObjcProperties:
    def __init__(self, ea):
        self.property_list = list()

#        print '%08x: Parsing properties' % ea
        entry_size = idc.Dword(ea)
        num_entries = idc.Dword(ea + 4)

        ea = ea + 8
        for i in range(num_entries):
            var_name = idc.GetString(idc.Dword(ea), -1, idc.ASCSTR_C)
            var_type = idc.GetString(idc.Dword(ea + 4), -1, idc.ASCSTR_C)
            self.property_list.append({'name':var_name, 'type':var_type})
            ea = ea + entry_size
        return

    def __len__(self):
        return len(self.property_list)

    def __repr__(self):
        dump = ''
        for entry in self.property_list:
            dump += '%s: %s\n' % (entry['name'], entry['type'])
        return dump


class ObjcIvars:
    def __init__(self, ea):
        self.ivar_list = list()

#        print '%08x: Parsing ivars' % ea
        entry_size = idc.Dword(ea)
        num_entries = idc.Dword(ea + 4)

        ea = ea + 8
        for i in range(num_entries):
            ivar_offset = idc.Dword(idc.Dword(ea))
            ivar_name = idc.GetString(idc.Dword(ea + 4), -1, idc.ASCSTR_C)
            ivar_type = idc.GetString(idc.Dword(ea + 8), -1, idc.ASCSTR_C)
            self.ivar_list.append({'name':ivar_name, 'type':ivar_type, 'offset':ivar_offset})
            ea = ea + entry_size
        return

    def __len__(self):
        return len(self.ivar_list)

    def __repr__(self):
        dump = ''
        for entry in self.ivar_list:
            dump += '%s (%d): %s\n' % (entry['name'], entry['offset'], encoded_types.get(entry['type'], entry['type']))
        return dump


class ObjcMethods:
    def __init__(self, ea):
        self.method_list = list()

#        print '%08x: Parsing methods' % ea
        entry_size = idc.Dword(ea)
        num_entries = idc.Dword(ea + 4)

        ea = ea + 8
        for i in range(num_entries):
            method_name = idc.GetString(idc.Dword(ea), -1, idc.ASCSTR_C)
            method_type = idc.GetString(idc.Dword(ea + 4), -1, idc.ASCSTR_C)
            method_ea = idc.Dword(ea + 8)
            self.method_list.append({'name': method_name, 'type':method_type, 'addr':method_ea})
            ea = ea + entry_size
        return

    def __len__(self):
        return len(self.method_list)

    def __repr__(self):
        dump = ''
        for entry in self.method_list:
            dump += '%08x: %s\n' % (entry['addr'], decode_type(entry['name'], entry['type']))
        return dump


class ObjcProtocols:
    def __init__(self, ea):
        self.protocol_list = list()

#        print '%08x: Parsing protocols' % ea
        num_main_structs = idc.Dword(ea)
        ea = ea + 4

        for i in range(num_main_structs):
            struct_off = idc.Dword(ea)
            protocol_name = idc.GetString(idc.Dword(struct_off + 4), -1, idc.ASCSTR_C)
            protocol_list = idc.Dword(struct_off + 8)
            instance_methods = idc.Dword(struct_off + 0xC)
            class_methods = idc.Dword(struct_off + 0x14)

            if instance_methods:
                _inst = ObjcMethods(instance_methods)
            else:
                _inst = None

            if class_methods:
                _class = ObjcMethods(class_methods)
            else:
                _class = None

            if protocol_list:
                _meta = ObjcProtocols(protocol_list)
            else:
                _meta = None

            self.protocol_list.append({
                'name': protocol_name,
                'instance_methods': _inst,
                'class_methods': _class,
                'meta_protocols': _meta})
            ea = ea + 4
        return

    def __len__(self):
        return len(self.protocol_list)

    def __repr__(self):
        dump = ''
        for entry in self.protocol_list:
            dump += 'Protocol %s:\n' % entry['name']
            if entry['instance_methods'] and len(entry['instance_methods']):
                dump += '  Instance Methods:\n    '
                dump += repr(entry['instance_methods']).replace('\n', '\n    ')

            if entry['class_methods'] and len(entry['class_methods']):
                dump += '  Class Methods:\n    '
                dump += repr(entry['class_methods']).replace('\n', '\n    ')

            if entry['meta_protocols'] and len(entry['meta_protocols']):
                dump += '  Protocol list:\n    '
                dump += repr(entry['meta_protocols']).replace('\n', '\n    ')

        return dump


class ObjcClass:
    def __init__(self, ea):
        self.class_info = dict()

        objc_const_seg = idc.SegByBase(idc.SegByName('__objc_const'))
        objc_const_end = idc.SegEnd(objc_const_seg)

        self.class_info['meta_class'] = idc.Dword(ea)
        self.class_info['super_class'] = idc.Dword(ea + 4)
        self.class_info['cache'] = idc.Dword(ea + 8)
        self.class_info['vtable'] = idc.Dword(ea + 0xC)
        _class_def = idc.Dword(ea + 0x10)

        if _class_def < objc_const_seg or _class_def > objc_const_end:
            return

        self.class_info['top_class'] = idc.Dword(_class_def)
        self.class_info['instance_size'] = idc.Dword(_class_def + 8)

        name_off = idc.Dword(_class_def + 0x10)
        class_name = idc.GetString(name_off, -1, idc.ASCSTR_C)
        if not class_name:
            class_name = '[UNKNOWN]'
        self.class_info['name'] = class_name

        self.class_info['methods'] = list()
        self.class_info['protocols'] = list()
        self.class_info['ivars'] = list()
        self.class_info['properties'] = list()

        if idc.Dword(_class_def + 0x14):
            self.class_info['methods'] = ObjcMethods(idc.Dword(_class_def + 0x14))

        if idc.Dword(_class_def + 0x18):
            self.class_info['protocols'] = ObjcProtocols(idc.Dword(_class_def + 0x18))

        if idc.Dword(_class_def + 0x1C):
            self.class_info['ivars'] = ObjcIvars(idc.Dword(_class_def + 0x1C))

        if idc.Dword(_class_def + 0x24):
            self.class_info['properties'] = ObjcProperties(idc.Dword(_class_def + 0x24))

        return

    def dump(self):
        if not self.class_info.has_key('name'):
            return
        print 'Class: %s' % self.class_info['name']
        print 'Attributes:'
        print '  IsTopClass: %d' % self.class_info['top_class']
        print '  Instance Size: %d' % self.class_info['instance_size']
        print '  Methods: %d' % len(self.class_info['methods'])
        print '  Protocols: %d' % len(self.class_info['protocols'])
        print '  Instance Vars: %d' % len(self.class_info['ivars'])
        print '  properties: %d' % len(self.class_info['properties'])

        if len(self.class_info['methods']):
            print 'Method list:\n  %s' % repr(self.class_info['methods']).replace('\n', '\n  ')

        if len(self.class_info['protocols']):
            print 'Protocols:\n  %s' % repr(self.class_info['protocols']).replace('\n', '\n  ')

        if len(self.class_info['ivars']):
            print 'Instance variables:\n  %s' % repr(self.class_info['ivars']).replace('\n', '\n  ')

        if len(self.class_info['properties']):
            print 'properties:\n  %s' % repr(self.class_info['properties']).replace('\n', '\n  ')


def main():
    objc_data_seg = idc.SegByBase(idc.SegByName('__objc_data'))
    if objc_data_seg == idc.BADADDR:
        print 'Cannot locate objc_data segment'
        return

    ea = objc_data_seg
    while ea < idc.SegEnd(objc_data_seg):
        objc_class = ObjcClass(ea)
        objc_class.dump()
        ea = ea + 0x14

def decode_type(name, type):
    global encoded_types

    list_types = re.split('\d+', type)
    if list_types[0][0] in '{[(':
        proto = list_types[0]
    else:
        proto = encoded_types.get(list_types[0], 'unknown ' + list_types[0])

    proto += ' ' + name + '('
    for t in list_types[3:]:
        if not t:
            continue
        if len(t) > 1 and t[0] in '{[(':
            proto += t + ', '
        else:
            proto += encoded_types.get(t, 'unknown ' + t) + ', '
    proto = proto.rstrip(' ,') + ')'
    return proto

if __name__ == '__main__':
    main()
    print 'Done.'
