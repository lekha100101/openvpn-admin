# Git: как записать `upgrade_openvpn_admin.sh` в репозиторий

Если вы изменили `upgrade_openvpn_admin.sh`, сохраните его в Git так:

```bash
git status
git add upgrade_openvpn_admin.sh
git commit -m "chore: update upgrade_openvpn_admin.sh"
git push origin <ваша-ветка>
```

Проверить, что файл попал в последний коммит:

```bash
git show --name-only --oneline -n 1
```
