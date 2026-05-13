import { test, expect } from 'playwright/test';

test('embedded app supports query, reverse, bulk, and history trace navigation', async ({ page }) => {
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
