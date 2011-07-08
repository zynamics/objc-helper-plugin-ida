import idaapi, idc, idautils
import re
import time

var_re = re.compile(', \[es?b?p.*[\+-](?P<varname>\w+)\]')


def track_param(ea, min_ea, op_type, op_val):
  '''
  trace_param: ea, min_ea, op_type, op_val

  Taking ea as start, this function does basic backtrace of
  an operand (defined by op_type and op_val) until it finds
  a data reference which we consider the "source". It stops
  when ea < min_ea (usually the function start).

  It does not support arithmetic or complex modifications of
  the source. This will be improved on future versions.
  '''
  global msgsend, var_re

  ea_call = ea
  while ea != idc.BADADDR and ea != min_ea:
    ea = idc.PrevHead(ea, min_ea)

    if idc.GetMnem(ea) not in ['lea', 'mov']:
      continue

    if idc.GetOpType(ea, 0) == op_type and idc.GetOperandValue(ea, 0) == op_val:
      if idc.GetOpType(ea, 1) == idc.o_displ:
        if ', [esp' in idc.GetDisasm(ea) or ', [ebp' in idc.GetDisasm(ea):
          if 'arg_' in idc.GetDisasm(ea):
          # We don't track function arguments
            return None

          # We only track stack variables
          try:
            var_name = var_re.search(idc.GetDisasm(ea)).group('varname')
            op_type = idc.GetOpType(ea, 1)
          except:
            print '%08x: Unable to recognize variable' % ea
            return None

          while ea != idc.BADADDR and ea > min_ea:
            if idc.GetMnem(ea) == 'mov' or idc.GetMnem(ea) == 'lea' and var_name in idc.GetDisasm(ea):
              # New reg to track
              op_val = idc.GetOperandValue(ea, 0)
              break
            ea = idc.PrevHead(ea, min_ea)

      elif idc.GetOpType(ea, 1) == idc.o_mem:
        # Got the final reference
        refs = list(idautils.DataRefsFrom(ea))
        if not refs:
          local_ref = idc.GetOperandValue(ea, 1)
          far_ref = idc.Dword(local_ref)
        else:
          while len(refs) > 0:
            far_ref = refs[0]
            refs = list(idautils.DataRefsFrom(refs[0]))
        return far_ref

      elif idc.GetOpType(ea, 1) == idc.o_reg:
        # Direct reg-reg assignment
        op_val = idc.GetOperandValue(ea, 1)
        op_type =  idc.GetOpType(ea, 1)
      else:
        # We don't track o_phrase or other complex source operands :(
        return None

  return None



def fix_callgraph(msgsend, segname, class_param, sel_param):
  '''
  fix_callgraph: msgsend, segname, class_param, sel_param

  Given the msgsend flavour address as a parameter, looks
  for the parameters (class and selector, identified by
  class_param and sel_param) and creates a new segment where
  it places a set of dummy calls named as classname_methodname
  (we use method instead of selector most of the time).
  '''

  t1 = time.time()
  if not msgsend:
    print 'ERROR: msgSend not found'
    return

  total = 0
  resolved = 0
  call_table = dict()


  for xref in idautils.XrefsTo(msgsend, idaapi.XREF_ALL):
    total += 1
    ea_call = xref.frm
    func_start = idc.GetFunctionAttr(ea_call, idc.FUNCATTR_START)
    if not func_start or func_start == idc.BADADDR:
      continue
    ea = ea_call

    method_name_ea = track_param(ea, func_start, idc.o_displ, sel_param)
    if method_name_ea:
      method_name = idc.GetString(method_name_ea, -1, idc.ASCSTR_C)
      if not method_name:
        method_name = ''
    else:
      method_name = ''

    class_name_ea = track_param(ea, func_start, idc.o_phrase, class_param)
    if class_name_ea:
      class_name = idc.GetString(class_name_ea, -1, idc.ASCSTR_C)
      if not class_name:
        class_name = ''
    else:
      class_name = ''

    if not method_name and not class_name:
      continue

    # Using this name convention, if the class and method
    # are identified by IDA, the patched call will point to
    # the REAL call and not one of our dummy functions
    #
    class_name = class_name.replace('_objc_class_name_', '')

    new_name = '_[' + class_name + '_' + method_name + ']'
    call_table[ea_call] = new_name
    resolved += 1

  print '\nFinal stats:\n\t%d total calls, %d resolved' % (total, resolved)
  print '\tAnalysis took %.2f seconds' % (time.time() - t1)

  if resolved == 0:
    print 'Nothing to patch.'
    return

  print 'Adding new segment to store new nullsubs'

  # segment size = opcode ret (4 bytes) * num_calls
  seg_size = resolved * 4
  seg_start = idc.MaxEA() + 4
  idaapi.add_segm(0, seg_start, seg_start + seg_size, segname, 'CODE')

  print 'Patching database...'
  seg_ptr = seg_start
  for ea, new_name in call_table.items():
    if idc.LocByName(new_name) != idc.BADADDR:
      offset = (idc.LocByName(new_name) - ea) & idc.BADADDR
    else:
      # create code and name it
      idc.PatchDword(seg_ptr, 0x90) # nop
      idc.MakeName(seg_ptr, new_name)
      idc.MakeCode(seg_ptr)
      idc.MakeFunction(seg_ptr, seg_ptr + 4)
      idc.MakeRptCmt(seg_ptr, new_name)
      offset = seg_ptr - ea
      seg_ptr += 4

    dw = offset - 5
    idc.PatchByte(ea, 0xE8)
    idc.PatchDword(ea + 1, dw)


def make_offsets(segname):
  segea = idc.SegByBase(idc.SegByName(segname))
  segend = idc.SegEnd(segea)

  while segea < segend:
    idc.OpOffset(segea, 0)
    ptr = idc.Dword(segea)
    idc.OpOffset(ptr, 0)
    segea += 4

if __name__ == '__main__':
  make_offsets('__cls_refs')
  make_offsets('__message_refs')
  idaapi.analyze_area(idc.MinEA(), idc.MaxEA())
  fix_callgraph(idc.LocByName('_objc_msgSend'), 'msgSend', 4, 4)
  fix_callgraph(idc.LocByName('_objc_msgSendSuper'), 'msgSendSuper', 4, 4)
  idaapi.analyze_area(idc.MinEA(), idc.MaxEA())
  print 'Done.'
