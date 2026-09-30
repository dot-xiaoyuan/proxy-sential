import { useUrlState } from '../shared/ui/useUrlState'
import { useState } from "react";
import {
  ApartmentOutlined,
  EnvironmentOutlined,
  WifiOutlined,
} from "@ant-design/icons";
import {
  Button,
  Card,
  Col,
  Empty,
  Form,
  Input,
  List,
  Modal,
  Row,
  Select,
  Space,
  Statistic,
  Tabs,
  Tag,
  Typography,
  message,
} from "antd";

import { can } from "../shared/auth/permissions";
import {
  useOrganization,
  useOrganizationList,
  useOrganizationMutation,
  useSession,
} from "../shared/api/queries";
import {
  AppErrorAlert,
  AppLoadingState,
  AppPageHeader,
  AppServerPagination,
  useServerPagination,
} from "../shared/ui";

type OrganizationKind =
  "campuses" | "buildings" | "network-zones" | "access-points";

export function OrganizationPage() {
 const [activeTab,setActiveTab]=useUrlState('tab','campuses',['campuses','zones']);
  const campusPage = useServerPagination("campuses_");
  const zonePage = useServerPagination("zones_");
  const query = useOrganization();
  const campusList = useOrganizationList("campuses", {
    limit: campusPage.pageSize,
    cursor: campusPage.cursor,
  });
  const zoneList = useOrganizationList("network_zones", {
    limit: zonePage.pageSize,
    cursor: zonePage.cursor,
  });
  const session = useSession();
  const mutation = useOrganizationMutation();
  const [kind, setKind] = useState<OrganizationKind | null>(null);
  const [form] = Form.useForm<Record<string, string>>();
  if (query.isLoading) return <AppLoadingState rows={6} />;
  if (query.isError || !query.data)
    return <AppErrorAlert title="校园组织与网络区域加载失败" />;
  const data = query.data;
  const writable = !!session.data && can(session.data, "organization:write");
  const open = (value: OrganizationKind) => {
    form.resetFields();
    setKind(value);
  };
  const submit = async () => {
    if (!kind) return;
    const values = await form.validateFields();
    const payload: Record<string, unknown> = { ...values };
    if (kind === "network-zones") {
      payload.cidrs = (values.cidrs ?? "")
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);
      payload.ssids = (values.ssids ?? "")
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);
      payload.vlans = (values.vlans ?? "")
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);
    }
    await mutation.mutateAsync({ kind, payload });
    setKind(null);
    message.success("组织与网络位置映射已保存");
  };
  return (
    <main className="page">
      <AppPageHeader
        title="校区与网络区域"
        subtitle="维护单校多校区、楼宇、网络区域和接入设备映射"
        loading={query.isFetching}
        onRefresh={() => void query.refetch()}
        extra={
          writable ? (
            <Space wrap>
              <Button onClick={() => open("campuses")}>新增校区</Button>
              <Button onClick={() => open("buildings")}>新增楼宇</Button>
              <Button onClick={() => open("network-zones")}>
                新增网络区域
              </Button>
              <Button type="primary" onClick={() => open("access-points")}>
                新增接入点
              </Button>
            </Space>
          ) : undefined
        }
      />
      <Row className="page-contained-row" gutter={[16, 16]}>
        <Col xs={24} md={8}>
          <Card>
            <Statistic
              prefix={<EnvironmentOutlined />}
              title="校区"
              value={data.campuses.length}
            />
          </Card>
        </Col>
        <Col xs={24} md={8}>
          <Card>
            <Statistic
              prefix={<ApartmentOutlined />}
              title="楼宇"
              value={data.buildings.length}
            />
          </Card>
        </Col>
        <Col xs={24} md={8}>
          <Card>
            <Statistic
              prefix={<WifiOutlined />}
              title="接入点/NAS"
              value={data.access_points.length}
            />
          </Card>
        </Col>
      </Row>
      <Card className="surface-card margin-top-md operations-tabs-surface">
        <Tabs activeKey={activeTab} onChange={setActiveTab}
          destroyOnHidden
          items={[
            {
              key: "campuses",
              label: "校区与楼宇",
              children: (
                <>
                  {(campusList.data?.items.length ?? 0) === 0 ? (
                    <Empty description="尚未导入校园组织数据" />
                  ) : (
                    <List
                      dataSource={campusList.data?.items ?? []}
                      renderItem={(campus) => (
                        <List.Item>
                          <List.Item.Meta
                            title={
                              <span className="nowrap-cell">
                                {campus.name} <Tag>{campus.code}</Tag>
                              </span>
                            }
                            description={`${data.buildings.filter((item) => item.campus_id === campus.campus_id).length} 栋楼宇`}
                          />
                        </List.Item>
                      )}
                    />
                  )}
                  <AppServerPagination
                    page={campusPage.page}
                    pageSize={campusPage.pageSize}
                    total={campusList.data?.page.total ?? 0}
                    onChange={campusPage.update}
                  />
                </>
              ),
            },
            {
              key: "zones",
              label: "网络区域与接入点",
              children: (
                <>
                  {(zoneList.data?.items.length ?? 0) === 0 ? (
                    <Empty description="尚未配置 VLAN、SSID 或网段映射" />
                  ) : (
                    <List
                      dataSource={zoneList.data?.items ?? []}
                      renderItem={(zone) => (
                        <List.Item>
                          <List.Item.Meta
                            title={
                              <span className="list-cell-nowrap">
                                {zone.name}
                              </span>
                            }
                            description={
                              <Typography.Text
                                className="list-cell-nowrap"
                                type="secondary"
                              >
                                SSID {zone.ssids.join("、") || ""} · VLAN{" "}
                                {zone.vlans.join("、") || ""}
                              </Typography.Text>
                            }
                          />
                        </List.Item>
                      )}
                    />
                  )}
                  <AppServerPagination
                    page={zonePage.page}
                    pageSize={zonePage.pageSize}
                    total={zoneList.data?.page.total ?? 0}
                    onChange={zonePage.update}
                  />
                </>
              ),
            },
          ]}
        />
      </Card>
      <Modal
        title="维护组织与网络位置"
        open={kind !== null}
        confirmLoading={mutation.isPending}
        onCancel={() => setKind(null)}
        onOk={() => void submit()}
      >
        <Form form={form} layout="vertical">
          {kind === "campuses" && (
            <>
              <Form.Item
                name="campus_id"
                label="校区 ID"
                rules={[{ required: true }]}
              >
                <Input />
              </Form.Item>
              <Form.Item
                name="code"
                label="校区编码"
                rules={[{ required: true }]}
              >
                <Input />
              </Form.Item>
              <Form.Item
                name="name"
                label="校区名称"
                rules={[{ required: true }]}
              >
                <Input />
              </Form.Item>
            </>
          )}
          {kind !== "campuses" && (
            <Form.Item
              name="campus_id"
              label="所属校区"
              rules={[{ required: true }]}
            >
              <Select
                options={data.campuses.map((item) => ({
                  value: item.campus_id,
                  label: item.name,
                }))}
              />
            </Form.Item>
          )}
          {kind === "buildings" && (
            <>
              <Form.Item
                name="building_id"
                label="楼宇 ID"
                rules={[{ required: true }]}
              >
                <Input />
              </Form.Item>
              <Form.Item
                name="code"
                label="楼宇编码"
                rules={[{ required: true }]}
              >
                <Input />
              </Form.Item>
              <Form.Item
                name="name"
                label="楼宇名称"
                rules={[{ required: true }]}
              >
                <Input />
              </Form.Item>
            </>
          )}
          {kind === "network-zones" && (
            <>
              <Form.Item
                name="network_zone_id"
                label="区域 ID"
                rules={[{ required: true }]}
              >
                <Input />
              </Form.Item>
              <Form.Item name="building_id" label="楼宇">
                <Select
                  allowClear
                  options={data.buildings.map((item) => ({
                    value: item.building_id,
                    label: item.name,
                  }))}
                />
              </Form.Item>
              <Form.Item
                name="name"
                label="区域名称"
                rules={[{ required: true }]}
              >
                <Input />
              </Form.Item>
              <Form.Item name="cidrs" label="网段（逗号分隔）">
                <Input />
              </Form.Item>
              <Form.Item name="ssids" label="SSID（逗号分隔）">
                <Input />
              </Form.Item>
              <Form.Item name="vlans" label="VLAN（逗号分隔）">
                <Input />
              </Form.Item>
            </>
          )}
          {kind === "access-points" && (
            <>
              <Form.Item
                name="access_point_id"
                label="接入点 ID"
                rules={[{ required: true }]}
              >
                <Input />
              </Form.Item>
              <Form.Item name="building_id" label="楼宇">
                <Select
                  allowClear
                  options={data.buildings.map((item) => ({
                    value: item.building_id,
                    label: item.name,
                  }))}
                />
              </Form.Item>
              <Form.Item name="network_zone_id" label="网络区域">
                <Select
                  allowClear
                  options={data.network_zones.map((item) => ({
                    value: item.network_zone_id,
                    label: item.name,
                  }))}
                />
              </Form.Item>
              <Form.Item name="kind" label="类型" rules={[{ required: true }]}>
                <Select
                  options={[
                    { value: "ap", label: "无线 AP" },
                    { value: "nas", label: "NAS" },
                    { value: "switch", label: "交换机" },
                  ]}
                />
              </Form.Item>
              <Form.Item name="name" label="名称" rules={[{ required: true }]}>
                <Input />
              </Form.Item>
              <Form.Item name="management_ip" label="管理 IP">
                <Input />
              </Form.Item>
            </>
          )}
        </Form>
      </Modal>
    </main>
  );
}
