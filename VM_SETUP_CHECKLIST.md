# ✅ VirtualBox VM Setup Checklist

## 📥 **Downloads**
- [ ] Download VirtualBox for macOS
- [ ] Download Ubuntu 22.04 LTS ISO
- [ ] Install VirtualBox

## 🖥️ **VM Creation**
- [ ] Create new VM named "Linux Security Agent"
- [ ] Set memory to 4096 MB (4GB)
- [ ] Set disk size to 25 GB
- [ ] Attach Ubuntu ISO to VM

## 🐧 **Ubuntu Installation**
- [ ] Start VM and install Ubuntu
- [ ] Create user account (remember password!)
- [ ] Complete installation and reboot
- [ ] Install Guest Additions
- [ ] Reboot after Guest Additions

## 📁 **Project Transfer**
- [ ] Set up shared folder in VirtualBox
- [ ] Add user to vboxsf group
- [ ] Reboot VM
- [ ] Verify project files are accessible

## 🛡️ **Security Agent Setup**
- [ ] Run setup_linux_vm.sh script
- [ ] Test eBPF installation
- [ ] Verify all dependencies installed
- [ ] Test security agent runs successfully

## 🎯 **Demo Preparation**
- [ ] Practice running security agent
- [ ] Test demo scripts work
- [ ] Verify real-time monitoring
- [ ] Prepare talking points

## 🎓 **Ready for Professor Demo**
- [ ] VM runs smoothly
- [ ] Security agent shows real eBPF monitoring
- [ ] No fallback messages
- [ ] Demo scripts work perfectly
- [ ] Professional presentation ready

---

## ⏱️ **Time Estimates**
- **Downloads**: 30 minutes
- **VM Setup**: 45 minutes
- **Ubuntu Installation**: 30 minutes
- **Project Setup**: 15 minutes
- **Testing**: 15 minutes
- **Total**: ~2.5 hours

## 🚀 **Quick Start Commands**
```bash
# After VM is ready
cd /media/sf_security_agent
sudo ./setup_linux_vm.sh
sudo python3 security_agent.py --dashboard --threshold 30
```
