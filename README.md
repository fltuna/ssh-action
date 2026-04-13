# SSH Run Action

GitHub Actions 用の SSH コマンド実行アクション。 

## 使い方

```yaml
- uses: fltuna/ssh-action@v1
  with:
    host: ${{ secrets.SSH_HOST }}
    user: deploy
    key: ${{ secrets.SSH_PRIVATE_KEY }}
    script: |
      cd /app
      docker compose pull
      docker compose up -d
```
