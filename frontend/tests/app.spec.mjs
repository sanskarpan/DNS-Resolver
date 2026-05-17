import { test, expect } from 'playwright/test';

test('embedded app supports query, reverse, bulk, and history trace navigation', async ({ page }) => {
    await page.addInitScript(() => {
        localStorage.setItem('dnsresolver.controlPlaneToken', 'playwright-token');
    });
    await page.goto('/#not-a-page');

    await expect(page.locator('#connection-status .status-text')).toHaveText('Connected');
    await expect(page).toHaveURL(/#query$/);

    await page.fill('#query-domain', 'example.com');
    await page.selectOption('#query-type', 'A');
    await page.check('#query-trace');
    await page.click('#query-btn');

    await expect(page.locator('#query-result')).toContainText('example.com');
    await expect(page.locator('#query-result')).toContainText('NOERROR');
    await expect(page.locator('#query-trace-panel')).toContainText('Resolution Trace');

    await page.fill('#reverse-ip', '127.0.0.1');
    await page.click('#reverse-btn');
    await expect(page.locator('#reverse-result')).toContainText('1.0.0.127.in-addr.arpa.');

    await page.fill('#bulk-queries', 'example.com\nopenai.com');
    await page.click('#bulk-run-btn');
    await expect(page.locator('#bulk-result table')).toBeVisible();
    await expect(page.locator('#bulk-result')).toContainText('example.com');
    await expect(page.locator('#bulk-result')).toContainText('openai.com');

    await page.click('.nav-link[data-page="history"]');
    await expect(page).toHaveURL(/#history$/);
    await expect(page.locator('#history-tbody')).toContainText('example.com.');

    const exampleRow = page.locator('#history-tbody tr', { hasText: 'example.com.' }).first();
    await exampleRow.getByRole('button', { name: 'Trace' }).click();
    await expect(page).toHaveURL(/#trace$/);
    await expect(page.locator('#trace-detail')).toContainText('example.com.');

    await page.click('.back-link');
    await expect(page).toHaveURL(/#history$/);
    await expect(page.locator('#page-history')).toHaveClass(/active/);

    await page.click('.nav-link[data-page="settings"]');
    await page.fill('#blocklist-text', 'example.com');
    await page.click('#blocklist-save');
    await expect(page.locator('#settings-status')).toContainText('Blocklist updated');
    await expect(page.locator('#blocklist-save')).toBeVisible();
    await expect(page.locator('#blocklist-text')).toHaveValue('example.com');
});

test('embedded app handles auth-required and failure-path flows', async ({ page }) => {
    const unauthorized = await page.request.get('/api/v1/settings');
    expect(unauthorized.status()).toBe(401);

    await page.addInitScript(() => {
        localStorage.setItem('dnsresolver.controlPlaneToken', 'playwright-token');
    });
    await page.goto('/#settings');

    await page.fill('#auth-token', 'playwright-token');
    await page.click('#auth-token-save');
    await expect(page.locator('#auth-token-status')).toContainText('Token saved locally');

    await page.click('.nav-link[data-page="query"]');
    await page.fill('#reverse-ip', 'not-an-ip');
    await page.click('#reverse-btn');
    await expect(page.locator('#reverse-result')).toContainText('invalid ip');

    await page.click('.nav-link[data-page="compare"]');
    await page.fill('#compare-domain', 'example.com');
    await page.fill('#compare-servers', 'bad-server');
    await page.click('#compare-btn');
    await expect(page.locator('#compare-result')).toContainText('no valid servers');

    const missingAsset = await page.request.get('/js/does-not-exist.js');
    expect(missingAsset.status()).toBe(404);
});
