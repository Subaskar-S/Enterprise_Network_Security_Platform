import React from 'react';
import {
  Drawer,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemButton,
  Divider,
  Typography,
  Box,
  Collapse,
  IconButton,
} from '@mui/material';
import {
  Dashboard,
  Security,
  Warning,
  NetworkCheck,
  Assessment,
  Settings,
  ExpandLess,
  ExpandMore,
  Shield,
  BugReport,
  Analytics,
  Policy,
  MenuOpen,
} from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';

interface SidebarProps {
  open: boolean;
  onToggle: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({ open, onToggle }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const [expandedItems, setExpandedItems] = React.useState<string[]>([]);

  const handleItemClick = (path: string) => {
    navigate(path);
  };

  const handleExpandClick = (item: string) => {
    setExpandedItems(prev =>
      prev.includes(item)
        ? prev.filter(i => i !== item)
        : [...prev, item]
    );
  };

  const menuItems = [
    {
      id: 'dashboard',
      text: 'Dashboard',
      icon: <Dashboard />,
      path: '/dashboard',
    },
    {
      id: 'threats',
      text: 'Threat Detection',
      icon: <Security />,
      path: '/threats',
      children: [
        { text: 'Active Threats', path: '/threats/active' },
        { text: 'Threat Intelligence', path: '/threats/intelligence' },
        { text: 'AI Detection', path: '/threats/ai-detection' },
      ],
    },
    {
      id: 'incidents',
      text: 'Incident Response',
      icon: <Warning />,
      path: '/incidents',
      children: [
        { text: 'Open Incidents', path: '/incidents/open' },
        { text: 'Investigation', path: '/incidents/investigation' },
        { text: 'Response Playbooks', path: '/incidents/playbooks' },
      ],
    },
    {
      id: 'network',
      text: 'Network Security',
      icon: <NetworkCheck />,
      path: '/network',
      children: [
        { text: 'Network Topology', path: '/network/topology' },
        { text: 'Traffic Analysis', path: '/network/traffic' },
        { text: 'Firewall Rules', path: '/network/firewall' },
      ],
    },
    {
      id: 'compliance',
      text: 'Compliance',
      icon: <Policy />,
      path: '/compliance',
      children: [
        { text: 'SOC 2', path: '/compliance/soc2' },
        { text: 'ISO 27001', path: '/compliance/iso27001' },
        { text: 'Audit Logs', path: '/compliance/audit' },
      ],
    },
    {
      id: 'reports',
      text: 'Reports',
      icon: <Assessment />,
      path: '/reports',
      children: [
        { text: 'Security Reports', path: '/reports/security' },
        { text: 'Compliance Reports', path: '/reports/compliance' },
        { text: 'Performance Reports', path: '/reports/performance' },
      ],
    },
    {
      id: 'settings',
      text: 'Settings',
      icon: <Settings />,
      path: '/settings',
      children: [
        { text: 'User Management', path: '/settings/users' },
        { text: 'Integrations', path: '/settings/integrations' },
        { text: 'System Config', path: '/settings/system' },
      ],
    },
  ];

  const drawerWidth = open ? 240 : 60;

  return (
    <Drawer
      variant="permanent"
      sx={{
        width: drawerWidth,
        flexShrink: 0,
        '& .MuiDrawer-paper': {
          width: drawerWidth,
          boxSizing: 'border-box',
          backgroundColor: 'background.paper',
          borderRight: '1px solid',
          borderColor: 'divider',
          transition: 'width 0.3s',
        },
      }}
    >
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: open ? 'space-between' : 'center',
          p: 2,
          minHeight: 64,
        }}
      >
        {open && (
          <Box display="flex" alignItems="center">
            <Shield color="primary" sx={{ mr: 1 }} />
            <Typography variant="h6" noWrap>
              Security Platform
            </Typography>
          </Box>
        )}
        <IconButton onClick={onToggle} size="small">
          <MenuOpen />
        </IconButton>
      </Box>
      
      <Divider />
      
      <List sx={{ flexGrow: 1, pt: 1 }}>
        {menuItems.map((item) => (
          <React.Fragment key={item.id}>
            <ListItem disablePadding>
              <ListItemButton
                selected={location.pathname === item.path}
                onClick={() => {
                  if (item.children) {
                    handleExpandClick(item.id);
                  } else {
                    handleItemClick(item.path);
                  }
                }}
                sx={{
                  minHeight: 48,
                  justifyContent: open ? 'initial' : 'center',
                  px: 2.5,
                }}
              >
                <ListItemIcon
                  sx={{
                    minWidth: 0,
                    mr: open ? 3 : 'auto',
                    justifyContent: 'center',
                  }}
                >
                  {item.icon}
                </ListItemIcon>
                {open && (
                  <>
                    <ListItemText primary={item.text} />
                    {item.children && (
                      expandedItems.includes(item.id) ? <ExpandLess /> : <ExpandMore />
                    )}
                  </>
                )}
              </ListItemButton>
            </ListItem>
            
            {item.children && open && (
              <Collapse in={expandedItems.includes(item.id)} timeout="auto" unmountOnExit>
                <List component="div" disablePadding>
                  {item.children.map((child) => (
                    <ListItemButton
                      key={child.path}
                      selected={location.pathname === child.path}
                      onClick={() => handleItemClick(child.path)}
                      sx={{ pl: 4 }}
                    >
                      <ListItemText primary={child.text} />
                    </ListItemButton>
                  ))}
                </List>
              </Collapse>
            )}
          </React.Fragment>
        ))}
      </List>
    </Drawer>
  );
};

export default Sidebar;
