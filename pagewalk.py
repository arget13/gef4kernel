@register
class PageWalk(GenericCommand):
    """"""
    _cmdline_ = "pagewalk"
    _syntax_  = f"{_cmdline_}"

    page_offset  = 0
    addrmask     = ((1 << 52) - 1) & ~((1 << 12) - 1)
    present      = 1 << 0
    writable     = 1 << 1
    userpage     = 1 << 2
    # writethrough = 1 << 3
    # uncacheable  = 1 << 4
    # accessed     = 1 << 5
    # dirty        = 1 << 6
    pagesize     = 1 << 7
    globalpage   = 1 << 8
    noexecute    = 1 << 63

    def infoentry(cls, entry):
        info  = ""
        info += " : 0x%016x" % entry

        nextbase = entry & cls.addrmask
        if ((entry == 0) or 
            (Address(value = (nextbase + cls.page_offset)).dereference() == None)):
            info += " INVALID"
            return (None, info)

        info += " 0x%013x " % (entry & cls.addrmask)
        info += "  " if (entry & cls.noexecute) else "X "
        info += "U " if (entry & cls.userpage) else "S "
        info += "W " if (entry & cls.writable) else "R "
        info += "P " if (entry & cls.present) else "  "
        info += "G " if (entry & cls.globalpage) else ""
        info += "\n"
        return (nextbase, info)

    @only_if_gdb_running
    def do_invoke(cls, argv):
        itsuserpage   = True
        itswritable   = True
        itsexecutable = True

        if (len(argv) < 1):
            print("Usage: pagewalk <addr> [page_offset]")
            return False

        if (len(argv) < 2):
            if Address(value = 0xffff888000000000).dereference():
                cls.page_offset = 0xffff888000000000
            elif Address(value = 0xffff880000000000).dereference():
                cls.page_offset = 0xffff880000000000
            else:
                print("Error, couldn't determine PAGE_OFFSET")
                return False
        else:
            cls.page_offset = parse_address(argv[1])

        addr  = parse_address(argv[0])
        print("Virt addr: " + Color.blueify("0x%016x" % addr))


        details  = ""
        details += "\nDetails:\n"
        details += "PAGE_OFFSET: " + Color.blueify("0x%016x" % cls.page_offset)
        details += "\n"

        pml4base = gef.arch.register("$cr3")
        pml4idx = ((addr >> 39) & ((1 << 9) - 1))
        pml4  = Address(value = (pml4base + cls.page_offset + pml4idx * 8))
        pml4e = pml4.dereference()
        details += "PML4E\t" + Color.blueify("0x%16x" % pml4.value)
        (pdpbase, info) = cls.infoentry(pml4e)
        if pdpbase == None: return False
        details += info

        # Restrictions in a superior entry override lower entries' ones
        if not (pml4e & cls.userpage) : itsuserpage   = False
        if not (pml4e & cls.writable) : itswritable   = False
        if     (pml4e & cls.noexecute): itsexecutable = False

        pdpidx = ((addr >> 30) & ((1 << 9) - 1))
        pdp   = Address(value = (pdpbase + cls.page_offset + pdpidx * 8))
        pdpe  = pdp.dereference()
        details += "PDPE\t" + Color.blueify("0x%16x" % pdp.value)
        (pdbase, info) = cls.infoentry(pdpe)
        if pdbase == None: return False
        details += info

        if not (pdpe & cls.userpage) : itsuserpage   = False
        if not (pdpe & cls.writable) : itswritable   = False
        if     (pdpe & cls.noexecute): itsexecutable = False

        if(pdpe & cls.pagesize):
            print("Phys addr: 0x%013x" % (pdbase + (addr & ((1 << 30) - 1))), end = "")
            print(" (1GiB ", end = "")
            print("X " if itsexecutable else "  ", end = "")
            print("U " if itsuserpage   else "S ", end = "")
            print("W " if itswritable   else "R ", end = "")
            print("G " if (pdpe & cls.globalpage) else "  ", end = "")
            print(")")
            print(details)
            return True

        pdidx = ((addr >> 21) & ((1 << 9) - 1))
        pd   = Address(value = (pdbase + cls.page_offset + pdidx * 8))
        pde  = pd.dereference()
        details += "PDE\t" + Color.blueify("0x%16x" % pd.value)
        (ptbase, info) = cls.infoentry(pde)
        if ptbase == None: return False
        details += info

        if not (pde & cls.userpage) : itsuserpage   = False
        if not (pde & cls.writable) : itswritable   = False
        if     (pde & cls.noexecute): itsexecutable = False

        if(pde & cls.pagesize):
            print("Phys addr: 0x%013x" % (ptbase + (addr & ((1 << 21) - 1))), end = "")
            print(" (2MiB ", end = "")
            print("X " if itsexecutable else "  ", end = "")
            print("U " if itsuserpage   else "S ", end = "")
            print("W " if itswritable   else "R ", end = "")
            print("G " if (pde & cls.globalpage) else "  ", end = "")
            print(")")
            print(details)
            return True

        ptidx = ((addr >> 12) & ((1 << 9) - 1))
        pt   = Address(value = (ptbase + cls.page_offset + ptidx * 8))
        pte  = pt.dereference()
        details += "PTE\t" + Color.blueify("0x%16x" % pt.value)
        (page, info) = cls.infoentry(pte)
        if page == None: return False
        details += info

        if not (pte & cls.userpage) : itsuserpage   = False
        if not (pte & cls.writable) : itswritable   = False
        if     (pte & cls.noexecute): itsexecutable = False

        print("Phys addr: 0x%013x" % (page + (addr & ((1 << 12) - 1))), end = "")
        print(" (4KiB ", end = "")
        print("X " if itsexecutable else "  ", end = "")
        print("U " if itsuserpage   else "S ", end = "")
        print("W " if itswritable   else "R ", end = "")
        print("G " if (pte & cls.globalpage) else "  ", end = "")
        print(")")
        print(details)
        return True
        
